#!/usr/bin/env python3

import sys
import os
import shutil

def _copy_artifacts_to_results():
    os.makedirs(paths.relative_path("result"), exist_ok = True)

    gen.copy_root_ca_certificate_and_key_pair()
    gen.copy_leaf_certificate_and_key_pair("server")
    gen.copy_leaf_certificate_and_key_pair("client")

def generate_ca(opts):
    logger.debug("generate_ca() " + str(opts))
    cli.ensure_password_is_provided(opts)
    logger.info("Will generate a root CA")
    gen.generate_root_ca(opts)

def generate_cs(opts):
    logger.debug("generate_cd()")
    cli.ensure_password_is_provided(opts)
    logger.info("Will generate two certificate/key pairs (server and client)")
    gen.generate_server_certificate_and_key_pair_by_cn(opts)
    gen.generate_client_certificate_and_key_pair_by_cn(opts)
    logger.info("Generated certificates.")
    # _copy_artifacts_to_results()
    # logger.debug("Find generated certificates and private keys under ./result!")
    logger.info("Done! ")

def clean_cs(opts):
    logger.debug("clean_cs()")
    caIndexTxt = paths.root_ca_index_txt_path()
    if os.path.isfile(caIndexTxt): 
      logger.info("Cleaning {}".format(caIndexTxt))
      open(caIndexTxt, 'w').close()

    for s in [paths.leaf_pair_path(opts.common_name + "_server"),
              paths.leaf_pair_path(opts.common_name + "_client")
              ]:
        logger.info("Removing {}".format(s))
        try:
            shutil.rmtree(s)
        except FileNotFoundError:
            pass

def clean_ca(opts):
    logger.debug("clean_ca()")
    for s in [paths.root_ca_path()]:
        logger.info("Removing {}".format(s))
        try:
            shutil.rmtree(s)
        except FileNotFoundError:
            pass

def clean(opts):
    logger.debug("clean()")
    clean_ca(opts)
    clean_cs(opts)
    for s in [paths.result_path() ]:
        logger.info("Removing {}".format(s))
        try:
            shutil.rmtree(s)
        except FileNotFoundError:
            pass

def regenerate_cs(opts):
    logger.debug("regenerate_cs()")
    logger.debug("opts =  " + str(opts))
    clean_cs(opts)
    generate_cs(opts)

def regenerate(opts):
    clean(opts)
    generate_cs(opts)

def verify_cs(opts):
    logger.debug("verify_cs() " + str(opts))
    logger.info("Will verify generated certificates against the CA...")
    verify.verify_leaf_certificate_against_root_ca_by_cn(opts, "client")
    #verify.verify_leaf_certificate_against_root_ca(opts.common_name + "server")

def verify_pkcs12(opts):
    cli.ensure_password_is_provided(opts)

    logger.info("Will verify generated PKCS12 certificate stores...")
    verify.verify_pkcs12_store("client", opts)
    verify.verify_pkcs12_store("server", opts)

def info(opts):
    info.leaf_certificate_info("client")
    info.leaf_certificate_info("server")

def printOpts(opts):
    logger.debug("printOpts() " + str(opts))

commands = {"generate_cs":     generate_cs,
            "regenerate_cs":   regenerate_cs,
            "clean_cs":        clean_cs,
            "verify_cs":       verify_cs,
            "clean_ca":        clean_ca,
            "generate_ca":     generate_ca,
            "clean":           clean,
            "regen":           regenerate,
            "verify-pkcs12":   verify_pkcs12,
            "info":            info,
            "printopts":       printOpts}

if __name__ == "__main__":
    sys.path.append("..")
    from tls_gen.app_logging import *
    from tls_gen import cli
    from tls_gen import gen
    from tls_gen import paths
    from tls_gen import verify
    from tls_gen import info

    cli.run(commands)
