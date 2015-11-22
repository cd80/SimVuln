import pyximport;pyximport.install()
from SimVuln import *
if __name__ == '__main__':
    import os
    from time import time
##    base_dir = "D:/study/qemu-2.3.0/"
    base_dir = "D:/study/qemu-2.5.0-rc1/"
    CodeSensorPath = "D:/study/codeengn2015/CodeSensor.jar"

    last = time()
    print "[*] Start"
    sv = SimVuln()
    sv.tokens = ['<invalid>', '<EOR>', '<DOWN>', '<UP>', 'ALPHA_NUMERIC', 'AND', 'ARGUMENT', 'ASSIGN', 'ASSIGN_OP', 'BASE_CLASSES', 'BIT_OR', 'BIT_OR_ELEM', 'BRACKETS', 'CALLEE', 'CALL_TEMPLATE_LIST', 'CLASS_CONTENT', 'CLASS_DEF', 'CLASS_NAME', 'COLON', 'COMMENT', 'CONDITION', 'COND_EXPR', 'CPPCOMMENT', 'CTOR_EXPR', 'CTOR_INITIALIZER', 'CTOR_LIST', 'CURLIES', 'DECIMAL_LITERAL', 'DESTINATION', 'DOT', 'EQ_OPERATOR', 'EXPR', 'EXPR_STATEMENT', 'Exponent', 'FIELD', 'FLOATING_POINT_LITERAL', 'FOR_EXPR', 'FOR_INIT', 'FUNCTION_CALL', 'FUNCTION_DEF', 'FUNCTION_NAME', 'FloatTypeSuffix', 'HEX_LITERAL', 'HexDigit', 'INCLUDE_DIRECTIVE', 'INIT', 'INITIALIZER_ID', 'INIT_DECL_LIST', 'ITERATION', 'IntegerTypeSuffix', 'JUMP_STATEMENT', 'KEYWORD', 'LABEL', 'LVAL', 'NAME', 'NAMESPACE_DEF', 'OCTAL_LITERAL', 'OR', 'OTHER', 'PARAMETER_DECL', 'PARAMETER_LIST', 'POINTER', 'PREPROC', 'QMARK', 'REL_OPERATOR', 'RETURN_TYPE', 'RVAL', 'SELECTION', 'SIMPLE_DECL', 'SOURCE_FILE', 'SQUARES', 'STATEMENTS', 'STRING', 'TEMPLATE_DECL_SPECIFIER', 'TYPE', 'TYPE_DEF', 'TYPE_NAME', 'TYPE_SUFFIX', 'UNARY_EXPR', 'UNARY_OPERATOR', 'USING_DIRECTIVE', 'VAR_DECL', 'WHITESPACE', 'LEAF_NODE']
    sv.tokens_exclude = ["LEAF_NODE", "LVAL", "EXPR_STATEMENT", "WHITESPACE", "LABEL", "COLON", "BRACKETS", "<UP>", "<DOWN>", "<EOR>", "<invalid>", "CURLIES", "Exponent", "SOURCE_FILE", "FUNCTION_DEF", "FUNCTION_NAME", "NAME", "PARAMETER_LIST", "PARAMETER_DECL", "RETURN_TYPE", "TYPE_NAME"]
    c_files = []

    print "[*] walking directory [ %s ]"%base_dir
    for root, dirs, files in os.walk(base_dir):
        for name in files:
            if name[-2:] == '.c':
                c_files.append(os.path.join(root, name).replace("\\", "/"))
    print "Elapsed %d seconds"%(time() - last)
    last = time()
    
    print "[*] processing %d c files"%len(c_files)
    sv.process_cfile(c_files)
    function_count = len(sv.code_dict)
    print "Elapsed %d seconds"%(time()-last)
    last = time()
    
    print "[*] Tokenizing codes"
    count = 1
    for cur_func in sv.code_dict:
        print "[Tokenizing function %d/%d] %s"%(count, function_count, cur_func)
        count += 1
        sv.tokenize_function(CodeSensorPath, cur_func)
    print "Elapsed %d seconds"%(time()-last)
    last = time()

    vuln_func = {"fdctrl_write_data": ["2.3.0", "hw/block/fdc.c"], # CVE-2015-3456
                 "e1000_receive": ["1.3.1", "hw/e1000.c"],# CVE-2012-6075
                 "virtio_load": ["1.7.1", "hw/virtio/virtio.c"], # CVE-2013-6399
                 "usb_device_post_load": ["1.7.1", "hw/usb/bus.c"], # CVE-2013-4541
                 "scoop_gpio_handler_update": ["1.7.1", "hw/gpio/zaurus.c"], # CVE-2013-4540
                 "usb_host_handle_control": ["0.11.0", "usb-linux.c"],# CVE-2010-0297
                 "pciej_write": ["1.1.0", "hw/acpi_piix4.c"],
                 "ne2000_receive": ["2.4.0", "hw/net/ne2000.c"]} # CVE-2011-1751
    for cur in vuln_func:
        ver = vuln_func[cur][0]
        path = vuln_func[cur][1]
        cur_file = "D:/study/qemu-%s/%s"%(ver, path)
        f = open(cur_file, "r")
        cur_code = f.read()
        f.close()
        function_list, code_dict = sv._process_code(cur_file, cur_code, True)
        tokenized_code = sv.tokenize_function(CodeSensorPath, cur, code_dict, True)
        print "============================================================="
        print "Checking similar functions for [%s]\n"%(cur)
        sv.list_similar_functions(cur, tokenized_code)
            
##        sv.list_similar_functions(target="fdctrl_read_data")
    
