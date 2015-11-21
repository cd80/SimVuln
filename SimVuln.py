import re

##f = open("vaja.c", "r")
##f = open("D:/study/qemu-2.3.0/net/eth.c", "r")
##f = open("D:/study/qemu-2.3.0/libcacard/cac.c", "r")
##f = open("D:/study/qemu-2.3.0/libcacard/card_7816.c", "r")
##code = f.read()
##f.close()
def merge_dicts(*dict_args):
    '''
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    '''
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result
def dynamicTimeWarp(seqA, seqB, d = lambda x,y: abs(x-y)):
    # create the cost matrix
    numRows, numCols = len(seqA), len(seqB)
    cost = [[0 for _ in range(numCols)] for _ in range(numRows)]
 
    # initialize the first row and column
    cost[0][0] = d(seqA[0], seqB[0])
    for i in xrange(1, numRows):
        cost[i][0] = cost[i-1][0] + d(seqA[i], seqB[0])
 
    for j in xrange(1, numCols):
        cost[0][j] = cost[0][j-1] + d(seqA[0], seqB[j])
 
    # fill in the rest of the matrix
    for i in xrange(1, numRows):
        for j in xrange(1, numCols):
            choices = cost[i-1][j], cost[i][j-1], cost[i-1][j-1]
            cost[i][j] = min(choices) + d(seqA[i], seqB[j])
 
##    for row in cost:
##       for entry in row:
##          print "%03d" % entry,
##       print ""
    return cost[-1][-1]
class SimVuln():
    '''
    sv = SimVuln()
    sv.process_cfile(file, file, file, file, file)
    sv.
    '''
    def __init__(self):
        self.code = []
        self.function_list = {}
        # self.function_list[function_name] = file path
        self.code_list = []
        self.code_dict = {}
        # self.code_dict[function_name] = function code
        self.token_types = []
        self.tokenized_codes = {}
        # self.tokenized_codes[function_name] = tokenized function code
        self.similarity_dict = {}
        # self.similarity_rank[nth_target_function] = sorted_by_dtw_distance_in_ascending_order({function_name:dtw_distance})
    def _process_code(self, file_name, code, module_usage=False):    
        p = []
        p.append(re.compile(r"\s*//.*")) # single-line comments
        p.append(re.compile(r"\s*/\*.*?(\*/)", re.DOTALL)) # multi-line comments
        p.append(re.compile(r"\s*#.*")) # preprocessors
        p.append(re.compile(r"^\s+", re.MULTILINE)) # leading whitespaces
        p.append(re.compile(r"\s+$", re.MULTILINE)) # trailing whitespaces
##        p.append(re.compile("(struct|union|typedef)\s+[^\(]*?{(.|\s)*?}.*?;"))
##        p.append(re.compile(r"(typedef|struct|union)\s+?[^\(\);]*?(\{(.|\s)*?\})+.*?;", re.MULTILINE))
        ##print re.sub(pattern, lambda x: x, code)
##        p.append(re.compile(r"(typedef|struct|union)\s+?[^\(\);]*?(\{(.|\s)*?\})+(.|\s)*?;"))
        p.append(re.compile(r"(typedef|struct|union|static|const)\s+?[^\(\);]*?(\{(.|\s)*?\})+(.|\s)*?;"))
        good_code = code

        good_code = good_code.replace("\n{", "{")
        good_code = good_code.replace(",\n", ",")
        for pattern in p:
            good_code = pattern.sub(r"", good_code)
        depth = 0;
        distance_to_func_decl= -1
        func_def = ''
        cur_function_code = ''
        function_list = {}
        code_list = []
        code_dict = {}
        is_function = 0
        self.good_code = good_code
        first = 1
        for i in xrange(len(good_code)):
            if depth == 0:
                if good_code[i] == '{':
                    depth += 1
                    distance_to_func_decl = -1
                    while func_def.find("(") == -1:
                        if abs(distance_to_func_decl) > len(good_code[:i].split("\n")):
                            is_function = 0
                            func_def = ''
                            break
                        func_def = good_code[:i].split("\n")[distance_to_func_decl]
                        distance_to_func_decl-=1
                        if distance_to_func_decl == -10: # max distance for damn many arguments
                            is_function = 0
                            cur_function_code = ''
                            break # this one is not a function
                    if func_def.find("(") == -1 or func_def.find(";") != -1:  # this is not a function too
                        is_function = 0
                        func_def = ''
                        cur_function_code = ''
                        continue
                    func_def = func_def.split("(")[0]
                    func_def = func_def.split(" ")[-1]
                    if func_def.find("\t") != -1:
                        func_def = func_def.split("\t")[1]
                    func_def = func_def.replace("*", "")
                    if func_def == '':
                        is_function = 0
                        cur_function_code = ''
                        continue
                    p = re.compile("[a-zA-Z0-9_]+")
                    if p.match(func_def) is None or \
                       len(p.match(func_def).group()) != len(func_def):
                        is_function = 0
                        cur_function_code = ''
                        continue
                    is_function = 1 # function start
                    
                    function_list[func_def] = file_name
                    continue
            else:
                if good_code[i] == '{':
                    depth += 1
                    if is_function:
                        cur_function_code += '{'
                        continue
                if good_code[i] == '}':
                    depth -= 1
                    if is_function:
                        if depth == 0:
                            if func_def not in self.code_dict:
                                if module_usage == True:
                                    code_dict[func_def] = cur_function_code
                                else:
                                    self.code_dict[func_def] = cur_function_code
                                cur_function_code = ''
                            func_def = ''
                            is_function = 0
                            continue
                if is_function:
                    cur_function_code += good_code[i]
        if module_usage == True:
            return function_list, code_dict
        else:
            self.function_list = merge_dicts(self.function_list, function_list)
    def process_cfile(self, c_file):
        cur_code = ''
        count = 1
        len_cfile = len(c_file)
        if type(c_file) != type([]):
            c_file = [c_file]
        for cur_file in c_file:
            print "[%d/%d] %s"%(count,len_cfile, cur_file)
            count += 1
            f = open(cur_file, "r")
            cur_code = f.read()
            self._process_code(cur_file, cur_code)
            f.close()
    def tokenize_function(self, tokenizer_path, function_name, code_dict = {}, module_usage = False):
        ''' code must be in func_name(){ code~~~~ } form '''
        import subprocess
        tokens = self.tokens
        exclude_list = self.tokens_exclude
        if module_usage:
            pass
        else:
            code_dict = self.code_dict
    
        orig_code = code_dict[function_name]
        orig_code = "int main(){%s}"%orig_code # CodeSensor doesn't process code without function
        f = open("orig_%s.c"%function_name, "w")
        f.write(orig_code)
        f.close()
## http://stackoverflow.com/questions/7006238/how-do-i-hide-the-console-when-i-use-os-system-or-subprocess-call
##        si = subprocess.STARTUPINFO()
##        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        subprocess.call("java -jar %s %s > tokenized_%s.c"%(tokenizer_path, "orig_%s.c"%function_name, function_name), shell=True)
        f = open("tokenized_%s.c"%function_name, "r")
        tokenized_func = f.read()
        f.close()
        cut_codes = ''
        for i in tokenized_func.split("\n"):
            cur_token = i.split("\t")[0]
            if cur_token not in self.tokens_exclude:
                cut_codes += i.split("\t")[0]+"\n"
            else:
                pass
        subprocess.call("rm tokenized_%s.c orig_%s.c"%(function_name, function_name), shell=True)
        if module_usage == True:
            return cut_codes
        else:
            self.tokenized_codes[function_name] = cut_codes
    def list_similar_functions(self, target_tokenized_code):
        count = 1
        tokens = self.tokens
        exclude_list = self.tokens_exclude
        func_count = len(self.code_dict)
        tokenized_codes = self.tokenized_codes
        similarity_dict = {}
        target_array = []
        for i in target_tokenized_code.split("\n"):
            if len(i) == 0 or i == '\n':
                continue
            try:
                if i in exclude_list:
                    continue
                target_array.append(tokens.index(i))
            except:
                raise Exception, "Error in list_similar_functions[1]\n"
        for func in tokenized_codes:
            print "[counting similarity %d/%d] %s"%(count, func_count, func)
            count += 1
            tmp_array = []
            empty_func = 0
            for i in tokenized_codes[func].split("\n"):
                if len(i) == 0 or i == '\n':
                    continue
                try:
                    if i in exclude_list:
                        continue
                    tmp_array.append(tokens.index(i))
                except:
                    raise Exception, "Error in list_similar_functions[2]\n"#, tokens, i
            if len(tmp_array): # exclude empty func
                dtw_distance = dynamicTimeWarp(target_array, tmp_array)
                similarity_dict[func] = dtw_distance
        import operator
        sim_dict = sorted(similarity_dict.items(), key=operator.itemgetter(1))
        print "%s\t%s\t%s"%("FUNC_NAME", "DTW_DISTANCE", "FILE_PATH")
        count = 0
        for func_name, similarity in sim_dict:
            count += 1
            print "%s\t%s\t%s"%(func_name, similarity, self.function_list[func_name])
            if count == 10:
                return
if __name__ == '__main__':
    import os
    from time import time
##    base_dir = "D:/study/qemu-2.3.0/"
    base_dir = "D:/study/qemu-2.3.0/"
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
                                     "pciej_write": ["1.1.0", "hw/acpi_piix4.c"]} # CVE-2011-1751
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
        sv.list_similar_functions(tokenized_code)
    
##        sv.list_similar_functions(target="fdctrl_read_data")
    
