// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Ownership additions over the generators' Rust syntax. Wire/schema declarations stay intact.

use std::collections::BTreeSet;

use syn::visit_mut::{self, VisitMut};
use syn::{parse_quote, Expr, Fields, GenericArgument, Item, Pat, PathArguments, Type};

/// Add recursive wiping to every message and oneof, and guarded decoding for collection members.
pub(super) fn messages(source: &str) -> syn::Result<String> {
    let mut file = syn::parse_file(source)?;
    message_items(&mut file.items)?;
    let tokens: proc_macro2::TokenStream = parse_quote! { #file };
    Ok(tokens.to_string())
}

fn message_items(items: &mut Vec<Item>) -> syn::Result<()> {
    let mut additions = Vec::new();
    for item in items.iter_mut() {
        match item {
            Item::Struct(message) => {
                let name = &message.ident;
                let fields: Vec<_> = message.fields.iter().map(|field| &field.ident).collect();
                additions.push(parse_quote! {
                    impl crate::proto::custody::Wipe for #name {
                        fn wipe(&mut self) {
                            #(crate::proto::custody::Wipe::wipe(&mut self.#fields);)*
                        }
                    }
                });
                if !is_copy(&message.attrs)? {
                    additions.push(parse_quote! {
                        impl Drop for #name {
                            fn drop(&mut self) { crate::proto::custody::Wipe::wipe(self); }
                        }
                    });
                }
                additions.push(parse_quote! {
                    impl<'de> crate::proto::custody::Decode<'de> for #name {
                        fn decode<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
                            serde::Deserialize::deserialize(de)
                        }
                    }
                });
                additions.push(parse_quote! {
                    impl crate::proto::custody::prost::MapValue for #name {
                        fn merge_value(
                            wire: ::prost::encoding::WireType,
                            value: &mut Self,
                            buf: &mut impl ::prost::bytes::Buf,
                            ctx: ::prost::encoding::DecodeContext,
                        ) -> Result<(), ::prost::DecodeError> {
                            ::prost::encoding::message::merge(wire, value, buf, ctx)
                        }
                    }
                });
            }
            Item::Enum(enumeration) => {
                let name = &enumeration.ident;
                let mut arms: Vec<syn::Arm> = Vec::new();
                let mut owns = false;
                for variant in &enumeration.variants {
                    let variant_name = &variant.ident;
                    match &variant.fields {
                        Fields::Unit => arms.push(parse_quote! { Self::#variant_name => {} }),
                        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                            owns = true;
                            arms.push(parse_quote! {
                                Self::#variant_name(value) => crate::proto::custody::Wipe::wipe(value)
                            });
                        }
                        _ => {
                            return Err(syn::Error::new_spanned(
                                variant,
                                "unsupported protobuf variant",
                            ))
                        }
                    }
                }
                additions.push(parse_quote! {
                    impl crate::proto::custody::Wipe for #name {
                        fn wipe(&mut self) { match self { #(#arms,)* } }
                    }
                });
                if owns {
                    if !is_copy(&enumeration.attrs)? {
                        additions.push(parse_quote! {
                            impl Drop for #name {
                                fn drop(&mut self) { crate::proto::custody::Wipe::wipe(self); }
                            }
                        });
                    }
                } else {
                    additions.push(parse_quote! {
                        impl<'de> crate::proto::custody::Decode<'de> for #name {
                            fn decode<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
                                serde::Deserialize::deserialize(de)
                            }
                        }
                    });
                }
            }
            Item::Mod(module) => {
                if let Some((_, items)) = &mut module.content {
                    message_items(items)?;
                }
            }
            _ => {}
        }
    }
    items.extend(additions);
    Ok(())
}

fn is_copy(attributes: &[syn::Attribute]) -> syn::Result<bool> {
    for attribute in attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("derive"))
    {
        let derives = attribute.parse_args_with(
            syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
        )?;
        if derives.iter().any(|path| path.is_ident("Copy")) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Guard pbjson's partial locals and recursively deserialize collections under those owners.
pub(super) fn serde(source: &str) -> syn::Result<String> {
    let mut file = syn::parse_file(source)?;
    let mut locals = Locals::default();
    locals.visit_file_mut(&mut file);
    let mut guards = Guards { locals: locals.0 };
    guards.visit_file_mut(&mut file);
    let tokens: proc_macro2::TokenStream = parse_quote! { #file };
    Ok(tokens.to_string())
}

#[derive(Default)]
struct Locals(BTreeSet<String>);

impl VisitMut for Locals {
    fn visit_local_mut(&mut self, local: &mut syn::Local) {
        if let (Pat::Ident(name), Some(init)) = (&local.pat, &mut local.init) {
            if name.ident.to_string().ends_with("__")
                && matches!(&*init.expr, Expr::Path(path) if path.path.is_ident("None"))
            {
                self.0.insert(name.ident.to_string());
                init.expr = Box::new(parse_quote! { crate::proto::custody::Guard::new(None) });
            }
        }
        visit_mut::visit_local_mut(self, local);
    }
}

struct Guards {
    locals: BTreeSet<String>,
}

impl Guards {
    fn local(&self, expr: &Expr) -> bool {
        matches!(expr, Expr::Path(path) if path.path.get_ident().is_some_and(|name| self.locals.contains(&name.to_string())))
    }
}

impl VisitMut for Guards {
    fn visit_item_impl_mut(&mut self, implementation: &mut syn::ItemImpl) {
        let visitor = implementation.trait_.as_ref().is_some_and(|(_, path, _)| {
            path.segments
                .last()
                .is_some_and(|segment| segment.ident == "Visitor")
        });
        let already_owned = implementation.items.iter().any(
            |item| matches!(item, syn::ImplItem::Fn(method) if method.sig.ident == "visit_string"),
        );
        if visitor && !already_owned {
            let borrowed = implementation.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "visit_str" => {
                    Some(method.clone())
                }
                _ => None,
            });
            if let Some(mut method) = borrowed {
                method.sig.ident = parse_quote! { visit_string };
                let Some(syn::FnArg::Typed(argument)) = method.sig.inputs.iter_mut().nth(1) else {
                    unreachable!("pbjson visit_str has a value argument")
                };
                let Pat::Ident(binding) = &*argument.pat else {
                    unreachable!("pbjson visit_str names its value")
                };
                let name = &binding.ident;
                argument.ty = Box::new(parse_quote! { String });
                method.block = parse_quote! {
                    {
                        let #name = crate::proto::custody::Guard::new(#name);
                        self.visit_str(&#name)
                    }
                };
                implementation.items.push(syn::ImplItem::Fn(method));
            }
        }
        visit_mut::visit_item_impl_mut(self, implementation);
    }

    fn visit_expr_path_mut(&mut self, expr: &mut syn::ExprPath) {
        let segments = &expr.path.segments;
        if segments.len() == 4
            && segments[0].ident == "pbjson"
            && segments[1].ident == "private"
            && segments[2].ident == "base64"
            && segments[3].ident == "encode"
        {
            expr.path = parse_quote! { crate::proto::custody::encode_base64 };
        }
        visit_mut::visit_expr_path_mut(self, expr);
    }

    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        match expr {
            Expr::Assign(assign) if self.local(&assign.left) => {
                self.visit_expr_mut(&mut assign.right);
                let left = &assign.left;
                assign.left = Box::new(parse_quote! { *#left });
                return;
            }
            Expr::MethodCall(call) if self.local(&call.receiver) => {
                for argument in &mut call.args {
                    self.visit_expr_mut(argument);
                }
                if call.method != "is_some" {
                    let receiver = &call.receiver;
                    call.receiver = Box::new(parse_quote! { #receiver.take() });
                }
                return;
            }
            Expr::MethodCall(call) if call.method == "next_value" => {
                // Use the generator's exact explicit type, or let the final field infer it.
                let ty: Type = call
                    .turbofish
                    .as_ref()
                    .and_then(|args| args.args.first())
                    .and_then(|arg| match arg {
                        GenericArgument::Type(ty) => Some(ty.clone()),
                        _ => None,
                    })
                    .unwrap_or_else(|| parse_quote! { _ });
                let mut ty = ty;
                self.visit_type_mut(&mut ty);
                call.method = parse_quote! { next_value_seed };
                call.turbofish = None;
                call.args = parse_quote! { crate::proto::custody::Seed::<#ty>::new() };
                return;
            }
            _ if self.local(expr) => {
                *expr = parse_quote! { #expr.take() };
                return;
            }
            _ => {}
        }
        visit_mut::visit_expr_mut(self, expr);
    }

    fn visit_type_path_mut(&mut self, ty: &mut syn::TypePath) {
        let segments = &ty.path.segments;
        if segments.len() == 3 && segments[0].ident == "pbjson" && segments[1].ident == "private" {
            let member = segments[2].clone();
            if member.ident == "BytesDeserialize" || member.ident == "NumberDeserialize" {
                ty.path = parse_quote! { crate::proto::custody::#member };
            }
        }
        // Nested Option/Vec/map type arguments also need their scalar adapters replaced.
        for segment in &mut ty.path.segments {
            if let PathArguments::AngleBracketed(arguments) = &mut segment.arguments {
                for argument in &mut arguments.args {
                    if let GenericArgument::Type(ty) = argument {
                        self.visit_type_mut(ty);
                    }
                }
            }
        }
    }
}
