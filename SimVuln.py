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
        self.similarity_rank = {}
        # self.similarity_rank[nth_target_function] = sorted_by_dtw_distance_in_ascending_order({function_name:dtw_distance})
    def _process_code(self, file_name, code):
        p = []
        p.append(re.compile(r"\s*//.*")) # single-line comments
        p.append(re.compile(r"\s*/\*.*?(\*/)", re.DOTALL)) # multi-line comments
        p.append(re.compile(r"\s*#.*")) # preprocessors
        p.append(re.compile(r"^\s+", re.MULTILINE)) # leading whitespaces
        p.append(re.compile(r"\s+$", re.MULTILINE)) # trailing whitespaces
        p.append(re.compile("(struct|union)\s+{"))
        ##print re.sub(pattern, lambda x: x, code)
        good_code = code

        good_code = good_code.replace("\n{", "{")
        for pattern in p:
            good_code = pattern.sub(r"", good_code)
        depth = 0;
        distance_to_func_decl= -1
        func_def = ''
        cur_function_code = ''
        function_list = {}
        code_list = []
        is_function = 0
        self.good_code = good_code
        first = 1
        for i in xrange(len(good_code)):
            if depth == 0:
                depth += 1
                if good_code[i] == '{':
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
                    if func_def.find("(") == -1:    # this is not a function too
                        is_function = 0
                        func_def = ''
                        cur_function_code = ''
                        continue
                    func_def = func_def.split("(")[0]
                    func_def = func_def.split(" ")[-1]
                    func_def = func_def.replace("*", "")
                    if func_def == '':
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
                                self.code_dict[func_def] = cur_function_code
                                cur_function_code = ''
                            func_def = ''
                            is_function = 0
                            continue
                if is_function:
                    cur_function_code += good_code[i]
        self.function_list = merge_dicts(self.function_list, function_list)
    def process_cfile(self, *args):
        cur_code = ''
        for c_file in args:
            if type(c_file) == type([]):
                for cur_file in c_file:
                    f = open(cur_file, "r")
                    cur_code = f.read()
                    self._process_code(cur_file, cur_code)
                    f.close()
            else:
                f = open(c_file, "r")
                cur_code = f.read()
                self._process_code(c_file, cur_code)
                f.close()
    def tokenize_function(self, tokenizer_path, function_name, debug=0):
        ''' code must be in func_name(){ code~~~~ } form '''
        import subprocess
        tokens = self.tokens
        exclude_list = self.tokens_exclude
        code_dict = self.code_dict
        self.function_name= function_name
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
            if cur_token not in sv.tokens_exclude:
                cut_codes += i.split("\t")[0]+"\n"
            else:
                pass
        
        subprocess.call("rm tokenized_%s.c orig_%s.c"%(function_name, function_name), shell=True)

        sv.tokenized_codes[function_name] = cut_codes
if __name__ == '__main__':
    import os
    base_dir = "D:/study/qemu-2.3.0/"
    CodeSensorPath = "D:/study/codeengn2015/CodeSensor.jar"

    sv = SimVuln()
    sv.tokens = ['<invalid>', '<EOR>', '<DOWN>', '<UP>', 'ALPHA_NUMERIC', 'AND', 'ARGUMENT', 'ASSIGN', 'ASSIGN_OP', 'BASE_CLASSES', 'BIT_OR', 'BIT_OR_ELEM', 'BRACKETS', 'CALLEE', 'CALL_TEMPLATE_LIST', 'CLASS_CONTENT', 'CLASS_DEF', 'CLASS_NAME', 'COLON', 'COMMENT', 'CONDITION', 'COND_EXPR', 'CPPCOMMENT', 'CTOR_EXPR', 'CTOR_INITIALIZER', 'CTOR_LIST', 'CURLIES', 'DECIMAL_LITERAL', 'DESTINATION', 'DOT', 'EQ_OPERATOR', 'EXPR', 'EXPR_STATEMENT', 'Exponent', 'FIELD', 'FLOATING_POINT_LITERAL', 'FOR_EXPR', 'FOR_INIT', 'FUNCTION_CALL', 'FUNCTION_DEF', 'FUNCTION_NAME', 'FloatTypeSuffix', 'HEX_LITERAL', 'HexDigit', 'INCLUDE_DIRECTIVE', 'INIT', 'INITIALIZER_ID', 'INIT_DECL_LIST', 'ITERATION', 'IntegerTypeSuffix', 'JUMP_STATEMENT', 'KEYWORD', 'LABEL', 'LVAL', 'NAME', 'NAMESPACE_DEF', 'OCTAL_LITERAL', 'OR', 'OTHER', 'PARAMETER_DECL', 'PARAMETER_LIST', 'POINTER', 'PREPROC', 'QMARK', 'REL_OPERATOR', 'RETURN_TYPE', 'RVAL', 'SELECTION', 'SIMPLE_DECL', 'SOURCE_FILE', 'SQUARES', 'STATEMENTS', 'STRING', 'TEMPLATE_DECL_SPECIFIER', 'TYPE', 'TYPE_DEF', 'TYPE_NAME', 'TYPE_SUFFIX', 'UNARY_EXPR', 'UNARY_OPERATOR', 'USING_DIRECTIVE', 'VAR_DECL', 'WHITESPACE', 'LEAF_NODE']
    sv.tokens_exclude = ["LEAF_NODE", "LVAL", "EXPR_STATEMENT", "WHITESPACE", "LABEL", "COLON", "BRACKETS", "<UP>", "<DOWN>", "<EOR>", "<invalid>", "CURLIES", "Exponent", "SOURCE_FILE", "FUNCTION_DEF", "FUNCTION_NAME", "NAME", "PARAMETER_LIST", "PARAMETER_DECL", "RETURN_TYPE", "TYPE_NAME"]
    c_files = []

    print "[*] walking directory [ %s ]"%base_dir
    for root, dirs, files in os.walk(base_dir):
        for name in files:
            if name[-2:] == '.c':
                c_files.append(os.path.join(root, name).replace("\\", "/"))
    print "[*] processing %d c files"%len(c_files)
    sv.process_cfile(c_files)

    DEBUG_NONE = 0
    DEBUG_PERCENTAGE = 1
    DEBUG_FUNC_NAME = 2

    print "[*] Tokenizing codes"
    for cur_func in sv.code_dict:
        sv.tokenize_function(CodeSensorPath, cur_func, debug=DEBUG_PERCENTAGE)
    
##    sv.list_similar_functions(target="fdctrl_read_data")
