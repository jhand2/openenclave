(* Copyright (c) Open Enclave SDK contributors.
   Licensed under the MIT License. *)

(** This module is Open Enclave's plugin for Intel's Edger8r, allowing
    us to share the same Enclave Definition Language, but emit our
    SDK's bindings. *)

open Intel.Ast
open Printf
open Common

(** [write_file] opens [filename] in the directory [dir] and emits a
    comment noting the file is auto generated followed by the
    [content], it then closes the file. *)
let write_file (content : string list) (filename : string) (dir : string) =
  let os =
    if dir = "." then open_out filename
    else open_out (dir ^ Intel.Util.separator_str ^ filename)
  in
  fprintf os "%s"
    (String.concat "\n"
       ( [
           "/*";
           " *  This file is auto generated by oeedger8r. DO NOT EDIT.";
           " */";
         ]
       @ content ));
  close_out os

let warn_non_portable_types (fd : func_decl) =
  (* Check if any of the parameters or the return type has the given
     root type. *)
  let uses_type (t : atype) =
    t = fd.rtype || List.exists (fun (p, _) -> t = get_param_atype p) fd.plist
  in
  let print_portability_warning ty =
    printf
      "Warning: Function '%s': %s has different sizes on Windows and Linux. \
       This enclave cannot be built in Linux and then safely loaded in Windows.\n"
      fd.fname ty
  in
  let print_portability_warning_with_recommendation ty recommendation =
    printf
      "Warning: Function '%s': %s has different sizes on Windows and Linux. \
       This enclave cannot be built in Linux and then safely loaded in \
       Windows. Consider using %s instead.\n"
      fd.fname ty recommendation
  in
  (* longs are represented as an Int type *)
  let long_t = Int { ia_signedness = Signed; ia_shortness = ILong } in
  let ulong_t = Int { ia_signedness = Unsigned; ia_shortness = ILong } in
  if uses_type WChar then print_portability_warning "wchar_t";
  if uses_type LDouble then print_portability_warning "long double";
  (* Handle long type *)
  if uses_type (Long Signed) || uses_type long_t then
    print_portability_warning_with_recommendation "long" "int64_t or int32_t";
  (* Handle unsigned long type *)
  if uses_type (Long Unsigned) || uses_type ulong_t then
    print_portability_warning_with_recommendation "unsigned long"
      "uint64_t or uint32_t"

let warn_signed_size_or_count_types (fd : func_decl) =
  let print_signedness_warning p =
    printf
      "Warning: Function '%s': Size or count parameter '%s' should not be \
       signed.\n"
      fd.fname p
  in
  (* Get the names of all size and count parameters for the function [fd]. *)
  let size_params =
    filter_map
      (fun (ptype, _) ->
        (* The size may be either a [count] or [size], and then
           either a number or string. We are interested in the
           strings, as they indicate named [size] or [count]
           parameters. *)
        let param_name { ps_size; ps_count } =
          match (ps_size, ps_count) with
          (* [s] is the name of the parameter as a string. *)
          | None, Some (AString s) | Some (AString s), None -> Some s
          (* TODO: Check for [Some (ANumber n)] that [n < 1] *)
          | _ -> None
        in
        (* Only variables that are pointers where [chkptr] is true may
           have size parameters. *)
        match ptype with
        | PTPtr (_, a) when a.pa_chkptr -> param_name a.pa_size
        | _ -> None)
      fd.plist
  in
  (* Print warnings for size parameters that are [Signed]. *)
  List.iter
    (fun (ptype, decl) ->
      let id = decl.identifier in
      if List.mem id size_params then
        match ptype with
        | PTVal (Long s | LLong s) when s = Signed ->
            print_signedness_warning id
        | PTVal (Int i) when i.ia_signedness = Signed ->
            print_signedness_warning id
        | _ -> ())
    fd.plist

let warn_size_and_count_params (fd : func_decl) =
  let print_size_and_count_warning { ps_size; ps_count } =
    match (ps_size, ps_count) with
    | Some (AString p), Some (AString q) ->
        Intel.Util.failwithf
          "Function '%s': simultaneous 'size' and 'count' parameters '%s' and \
           '%s' are not supported by oeedger8r.\n"
          fd.fname p q
    | _ -> ()
  in
  List.iter
    (fun (ptype, _) ->
      match ptype with
      | PTPtr (_, ptr_attr) when ptr_attr.pa_chkptr ->
          print_size_and_count_warning ptr_attr.pa_size
      | _ -> ())
    fd.plist

(** Generate the Enclave code. *)
let write_enclave_code (ec : enclave_content) (ep : Intel.Util.edger8r_params) =
  (* Short aliases for the trusted and untrusted function
     declarations. *)
  let tfs = ec.tfunc_decls in
  let ufs = ec.ufunc_decls in
  (* Validate Open Enclave supported EDL features. NOTE: This
     validation has the side effects of printed warnings or failure
     with an error message. *)
  if ep.use_prefix then
    Intel.Util.failwithf "--use_prefix option is not supported by oeedger8r.";
  List.iter
    (fun f ->
      if f.tf_is_priv then
        Intel.Util.failwithf
          "Function '%s': 'private' specifier is not supported by oeedger8r"
          f.tf_fdecl.fname)
    tfs;
  List.iter
    (fun f ->
      ( if f.uf_fattr.fa_convention <> CC_NONE then
        let cconv_str = get_call_conv_str f.uf_fattr.fa_convention in
        printf
          "Warning: Function '%s': Calling convention '%s' for ocalls is not \
           supported by oeedger8r.\n"
          f.uf_fdecl.fname cconv_str );
      if f.uf_fattr.fa_dllimport then
        Intel.Util.failwithf
          "Function '%s': dllimport is not supported by oeedger8r."
          f.uf_fdecl.fname;
      if f.uf_allow_list != [] then
        printf
          "Warning: Function '%s': Reentrant ocalls are not supported by Open \
           Enclave. Allow list ignored.\n"
          f.uf_fdecl.fname)
    ufs;
  (* Map warning functions over trusted and untrusted function
     declarations *)
  let ufuncs = List.map (fun f -> f.uf_fdecl) ufs in
  let tfuncs = List.map (fun f -> f.tf_fdecl) tfs in
  let funcs = List.append ufuncs tfuncs in
  List.iter
    (fun f ->
      warn_non_portable_types f;
      warn_signed_size_or_count_types f;
      warn_size_and_count_params f)
    funcs;
  (* End EDL validation. *)
  (* NOTE: The below code encapsulates all our file I/O. *)
  let args_h = ec.file_shortnm ^ "_args.h" in
  if ep.gen_trusted then (
    write_file (Headers.generate_args ec) args_h ep.trusted_dir;
    write_file
      (Headers.generate_trusted ec)
      (ec.file_shortnm ^ "_t.h") ep.trusted_dir;
    if not ep.header_only then
      write_file
        (Sources.generate_trusted ec ep)
        (ec.file_shortnm ^ "_t.c") ep.trusted_dir );
  if ep.gen_untrusted then (
    write_file (Headers.generate_args ec) args_h ep.untrusted_dir;
    write_file
      (Headers.generate_untrusted ec)
      (ec.file_shortnm ^ "_u.h") ep.untrusted_dir;
    if not ep.header_only then
      write_file
        (Sources.generate_untrusted ec ep)
        (ec.file_shortnm ^ "_u.c") ep.untrusted_dir );
  printf "Success.\n"

(** Install the plugin. *)
let _ =
  Printf.printf "Generating edge routines for the Open Enclave SDK.\n";
  Intel.Plugin.instance.available <- true;
  Intel.Plugin.instance.gen_edge_routines <- write_enclave_code
