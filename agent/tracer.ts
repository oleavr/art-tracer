import * as Java from "frida-java";
import { getApi } from "frida-java/lib/android";
import { getArtThreadFromEnv } from "frida-java/lib/android";
import { log } from "./logger";
import { test_client, send_log } from "./client_logger";
import  VM  from "frida-java/lib/vm"
import { prototype } from "stream";
import { print } from "util";
import { StdInstrumentationStackDeque, StdString } from "./tools";
const api = getApi();


export interface TraceCallbacks {
    onEnter(methodName: string | null): void;
    onLeave(methodName: string | null): void;
}

enum InstrumentationEvent {
    MethodEntered = 0x1,
    MethodExited = 0x2,
    MethodUnwind = 0x4,
    DexPcMoved = 0x8,
    FieldRead = 0x10,
    FieldWritten = 0x20,
    ExceptionCaught = 0x40,
    Branch = 0x80,
    InvokeVirtualOrInterface = 0x100,
}

const retainedHandles: any[] = [];  // to keep calbacks alive

let attachCurrentThread_attached = 0;

let userTraceCallbacks: TraceCallbacks;

let listener: NativePointer;
try {
    listener = makeListener();
} catch (e) {
    add_to_log("Shit: " + e.stack);
}

const runtime = api.artRuntime;
let methodRegex: RegExp = /.*/;
let classRegex: RegExp = /.*/;
const dlopen = getDlopen();
const dlsym = getDlsym();
const artlib : any = dlopen("/system/lib/libart.so");
const libcpp : any = dlopen("/system/lib/libc++.so");
const libc : any = dlopen("/system/lib/libc.so");
// HELPER CODE
//const helperPath = "/data/local/tmp/re.frida.server/libart-tracer-helper.so";
//const helper : any = dlopen(helperPath);
const method_Invoke: any = new NativeFunction(
    dlsym(artlib,"_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc"),
    "void",
    ["pointer","pointer","uint32","pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });

const operatorDelete: any = new NativeFunction(
    dlsym(libcpp ,"_ZdlPv")  ,
    "void",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
const getUtfLength: any = new NativeFunction(
    dlsym(artlib,"_ZN3art6mirror6String12GetUtfLengthEv"),
    "int32",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
const toCharArray: any = new NativeFunction(
    dlsym(artlib,"_ZN3art6mirror6String11ToCharArrayEPNS_6ThreadE"),
    "pointer",
    ["pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
const getData: any = new NativeFunction(
    dlsym(artlib ,"_ZNK3art6mirror14PrimitiveArrayItE7GetDataEv") ,
    "pointer",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });

const getNameAsString: any = new NativeFunction(
    dlsym(artlib,"_ZN3art9ArtMethod15GetNameAsStringEPNS_6ThreadE"),
    "pointer",
    ["pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    }); 

const findMethodForProxy: any = new NativeFunction(
    dlsym(artlib,"_ZN3art11ClassLinker18FindMethodForProxyEPNS_9ArtMethodE"),
    "pointer",
    ["pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    }); 
const runtimeAttachCurrentThread: any = new NativeFunction(
    dlsym(artlib,"_ZN3art7Runtime19AttachCurrentThreadEPKcbP8_jobjectb"),
    "bool",
    ["pointer","bool","pointer","bool"],
    {
        exceptions: ExceptionsBehavior.Propagate
    }); 
const getDescriptor: any = new NativeFunction(
    dlsym(artlib,"_ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE") as NativePointer,
    "pointer",
    ["pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
const fopen: any = new NativeFunction(
    dlsym(libc,"fopen"),
    "pointer",
    ["pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
const fprintf: any = new NativeFunction(
    dlsym(libc,"fprintf"),
    "int",
    ["pointer","pointer",'...'],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
const fclose: any = new NativeFunction(
    dlsym(libc,"fclose"),
    "int",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
            

const declaringClassOffset = 0;


var log_bloc: string = "";
var number_of_block_send = 0;
var current_number_of_lines = 0; 

function add_to_log(string: String){
    if (current_number_of_lines >  100){
        send_log(log_bloc);
        log_bloc = "";
        current_number_of_lines = 0;
        number_of_block_send = number_of_block_send + 1;
        log("++>NEW BLOCK SENT: " + number_of_block_send);
    } else {
        log_bloc = log_bloc + string;
        current_number_of_lines++;
        log(" adding new line " + current_number_of_lines);
    }
}


    
export function trace(userTraceCallbacks_: TraceCallbacks, methodRegex_: RegExp = /.*/, classRegex_: RegExp = /.*/) {
    methodRegex = methodRegex_;
    classRegex = classRegex_;
    userTraceCallbacks = userTraceCallbacks_;
    Java.perform(() => {
        log("trace() starting up 1");
        test_client();
        send_log("first bloc");
        



/*
to implement to log 
#include "stdio.h"
void WriteLogFile(const char* szString)
{
  #IFDEF DEBUG

  FILE* pFile = fopen("logFile.txt", "a");
  fprintf(pFile, "%s\n",szString);
  fclose(pFile);

  #ENDIF

}*/













        log("trace() starting up 2");
     
        const vm = new VM(api);
        const instrumentationOffset = 464;
        const instrumentation = runtime.add(instrumentationOffset);
        
        // HELPER CODE-- Just for me, the developper :) 
        const gdb_OutputMethodReturnValue: any = new NativeFunction(
        dlsym(artlib,"_ZN3art3Dbg23OutputMethodReturnValueEyPKNS_6JValueEPNS_4JDWP9ExpandBufE"),
        "void",
        ["uint64","pointer","pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
        log("printing the address of gdb::OutputMethodReturnValue " + gdb_OutputMethodReturnValue);
        log("code : \n ");
        printAsm(gdb_OutputMethodReturnValue, 1000);

        // END HELPER CODE
        const addListener: any = new NativeFunction(
            dlsym(artlib,"_ZN3art15instrumentation15Instrumentation11AddListenerEPNS0_23InstrumentationListenerEj"),
            "void",
            ["pointer","pointer","uint32"],
            {
                exceptions: ExceptionsBehavior.Propagate
            });
        //log("address Of addListener -- " + addListener);
        const enableDeoptimization: any = new NativeFunction(
            dlsym(artlib,"_ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv"),
            "void",
            ["pointer"],
            {
                exceptions: ExceptionsBehavior.Propagate
            });        
        //log("address Of enableDeoptimization " + enableDeoptimization);
        const deoptimizeEverything: any = new NativeFunction(
            dlsym(dlopen("/system/lib/libart.so"),"_ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEPKc"),
            "void",
            ["pointer","pointer"],
            {
                exceptions: ExceptionsBehavior.Propagate
            });
        //log("address Of deoptimizeEverything " + deoptimizeEverything);
        enableDeoptimization(instrumentation);
        const env = vm.getEnv();
        const threadHandle = getArtThreadFromEnv(env);
        //prepareDoptimization(instrumentation, Memory.allocUtf8String("frida"),threadHandle);

        if(Process.arch == "ia32") log("----------////////////// Archictecture  "  +   Process.arch);
     
        deoptimizeEverything(instrumentation, Memory.allocUtf8String("frida"));
        addListener(instrumentation, listener, InstrumentationEvent.MethodEntered /* | InstrumentationEvent.MethodExited | InstrumentationEvent.FieldRead | InstrumentationEvent.FieldWritten*/);
        


        //log("--------> after api: " + JSON.stringify(api)); 
        //log("to see what happen when deoptimisation is not enabled : method are called eather directly from jni or called when already compiled");
        //log("the overhead added by the deoptimisation is neglectable, the one to analyse is my code");
        //log("to see what it can be possible to do with injection , let see the taint tracking");
        //patchInvoke(); 
         
    }); 
}


function makeListener(): NativePointer {
    const numVirtuals = 11;

    const listener = Memory.alloc(Process.pointerSize);
    retainedHandles.push(listener);

    const vtable = Memory.alloc(numVirtuals * Process.pointerSize);
    retainedHandles.push(vtable);
    Memory.writePointer(listener, vtable);

    for (let i = 0; i !== numVirtuals; i++) {
        switch(i) { 
            case 2: { 
                const method = makeMethodEntered();
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
            case 3: { 
                const method = makeMethodExited();
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
            case 6: { 
                const method = makeFieldRead();
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
            case 7: { 
                const method = makeFieldWritten();
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            }
            default: { 
                const method = makeListenerMethod("vmethod" + i);
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
        } 
    }
    return listener;
}

function getNameFromStringObject(stringObject:NativePointer, thread: NativePointer):string|null{
    let length = getUtfLength(stringObject);
    let charArray = toCharArray(stringObject,thread);
    let datas = getData(charArray);     
    return Memory.readUtf16String(datas,length);
} 

function makeMethodEntered(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number): void => {
       //just test the method
        //if(!method.isNull()) log("-/testing this method : " +  Memory.readU32(method.add(8)));
        // NOW GETTING THE ARGUMENTS
        // there is one of the possibles listener call graph when the method is called
        //art_quick_to_interpreter_bridge
        //              |
        //              v
        //artQuickToInterpreterBridge
        //              |
        //              v
        //interpreter::EnterInterpreterFromDeoptimize(self, deopt_frame, from_code, &result)
        //              |
        //              v
        //Execute(self, code_item, *shadow_frame, value)
        //              |
        //              v
        //instrumentation->MethodEnterEvent(self, shadow_frame.GetThisObject(code_item->ins_size_),method, 0);
        //              |
        //              v
        //MethodEnterEventImpl(thread, this_object, method, dex_pc)
        //              |
        //              v
        //listener->MethodEntered(thread, thiz, method, dex_pc);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32"]);

    retainedHandles.push(callback);
    //we attach an interceptor to callback to have access to the stack of the current thread
    //to optimize----------------
    Interceptor.attach(callback, {
        onEnter: function (args) {
            var start = new Date().getTime();



            this.thread = args[1];
            this.method = args[3];
            this.thisObject = args[2];
            //log("MethodEntered()  from the Interceptor ---method=" + this.method + " context=" + JSON.stringify(this.context));
            let current_sp = this.context.sp; 
            let current_pc = this.context.pc;
            let stack_offset_counter = 0;
            let dword_size = 4;
            let dex_pc_offset = 28; //(7*Process.PointerSize)
            let dex_pc_ptr_offset = 12; //(3*Process.pointerSize)
            let code_item_offset = 16;
            let classLinker_offset = 284;
            let thread: NativePointer = this.thread;
            let method: NativePointer = this.method;
            let thisObject: NativePointer = this.thisObject;
            
            // GENERAL INFORMATIONS WE CAN OBTAIN IN ALL CASES, FOR NORMAL AND COMPILED METHODS  
            let methodNameStringObject = getNameAsString(method, thread); 
            const stringMethodName = getNameFromStringObject(methodNameStringObject,thread);

            /// user condition on the method Name
            add_to_log("testing method name" + stringMethodName + "regex " + methodRegex); 
            if(!methodRegex.test(stringMethodName as string)){
                add_to_log("method name does not match");
                return;  
            }
          
            /// GETTING THE CLASS NAME : APPROACH BY METHOD CLASS 
           
            const declaring_classHandle= method.add(declaringClassOffset);
            const declaring_class_ = ptr(Memory.readU32(declaring_classHandle));
            /// TRYING WITH THE DESCRIPTOR    const char* Class::GetDescriptor(std::string* storage)

            let rawClassName: string;
            const storage = new StdString();
            rawClassName = Memory.readUtf8String(getDescriptor(declaring_class_, storage)) as string;   
            storage.dispose();
            const className = rawClassName.substring(1, rawClassName.length - 1).replace(/\//g, ".");
            add_to_log("testing class name");
            if(!classRegex.test(className)){
                add_to_log("class name does not match");
                return;
            }

            add_to_log("thisObject=" + thisObject + ", \n method=" + method + ",\n descriptor=" + className + ",\n methodName=" + stringMethodName);

            // NOW LOOKING FOR THE SHORTY AND FOR THE ARGUMENTS

            //GETTING THE SHORTY
            let return_type_string: any;

    //TO GET THE SHORTY I NEED TO HAVE THE INTERFACE METHOD FIRST BY USING GetInterfaceMethodIfProxy()
            //IN THE ART SOURCE CODE, THIS METHOD CALLS Runtime::Current()->GetClassLinker()->FindMethodForProxy(this); AND RETURN THE RESULT 
            // AND BECAUSE THE LATEST IS EXPOSED, I WILL START BY IMPLEMENTING IT, I DONT USE THE CACHE AS IN THE GetInterfaceMethodIfProxy() 
            let class_linker: NativePointer = Memory.readPointer(runtime.add(classLinker_offset));  
            //log("classLinker : " + class_linker);
            let interfaceMethod = findMethodForProxy(class_linker, method);
            //log("Interface Method obtained" + interfaceMethod);

            // NOW GETTING THE SHORTY FROM THE INTERFACE METHOD (method_index means index in the corresponding method_ids in the dex_file)(and the methood_id is the index in string_ids)
            let declaringClass: NativePointer = Memory.readPointer(interfaceMethod);
            //log ("Declaring class = " + declaringClass);
            let dexCache: NativePointer = Memory.readPointer(declaringClass.add(16));
            //log ("Dexcache = " + dexCache);
            let dexfile: NativePointer = Memory.readPointer(dexCache.add(16));
            //log("dexFile" + dexfile);
            let dex_method_index: number = Memory.readU16(interfaceMethod.add(8));
            //log("dex_method_index" + dex_method_index);
            let method_ids: NativePointer =  Memory.readPointer(dexfile.add(48));
            //log("method_ids array" + method_ids);
            let proto_index: number = Memory.readU16(method_ids.add(dex_method_index*8 + 2));
            //log("proto index " + proto_index);
            let proto_ids: NativePointer =  Memory.readPointer(dexfile.add(52));
            //log("proto_ids array: " + proto_ids);
            let proto_index_final: number  =  ptr(proto_index).add(ptr(proto_index).shl(1)).toInt32();// - ----------------- to see deeply (okay just a compiler trick to multiply by 3)
            //log("proto index old:  caller " + proto_index_old);
            let proto_id_old: NativePointer = proto_ids.add(proto_index_final * 4);  /// can be used to obtain the return type
            //log("proto_id address  " + proto_id_old);
            let shorty_idx_old: NativePointer =  Memory.readPointer(proto_id_old);
            //log("shorty_idx  old " + shorty_idx_old);
            let string_ids: NativePointer = Memory.readPointer(dexfile.add(36));
            //log("string_ids array " + string_ids);
            let dex_file_begin: NativePointer = Memory.readPointer(dexfile.add(4));
            //log("dex_file_begin " + dex_file_begin);
            let prototype_string_offset_old: NativePointer = Memory.readPointer(string_ids.add(shorty_idx_old.shl(2))); // or *4
            //log("prototype_string offsett old " + prototype_string_offset_old);
            if(Memory.readPointer(dex_file_begin.add(prototype_string_offset_old)).equals(NULL)) log("****error in getting the shorty"); 
            let prototype_string_address_old: NativePointer = dex_file_begin.add(prototype_string_offset_old.add(1));
            //log("prototype_string_address : " + prototype_string_address_old);
            let shorty: any =  Memory.readUtf8String(prototype_string_address_old);
            add_to_log(" shorty = " + shorty);
            let type_ids =  Memory.readPointer(dexfile.add(40));

            if(shorty.length == 1){
                //log("need only to obtain the return type");
                if(shorty != "L"){
                    return_type_string = getPrimitiveTypeAsString(shorty);
                }else{
                    let return_type_idx: number =  Memory.readU16(proto_id_old.add(4));
                    return_type_string = getStringByTypeIndex(type_ids, return_type_idx, string_ids, dex_file_begin);
                    add_to_log("Return type in string " + return_type_string);

                }   
                //break;
            }else{
                // Obtaining the parameter list 
                let param_type_list: NativePointer = getProtoParameters(proto_id_old, dex_file_begin);
                //log(" address of the param type list " + param_type_list + " size " + Memory.readS32(param_type_list));

                let size =  Memory.readS32(param_type_list);
                let param_type_list_elt = param_type_list.add(4);
                
                
                for(let i = 0; i < size; i++) {
                    let typeItem: NativePointer = param_type_list_elt.add(i*2);
                    let type_idx: number = Memory.readU16(typeItem);
                    let descriptor_string = getStringByTypeIndex(type_ids, type_idx, string_ids, dex_file_begin);
                    add_to_log("parameter" + i + "type in string " + descriptor_string);

                }
                let return_type_idx: number =  Memory.readU16(proto_id_old.add(4));
                return_type_string = getStringByTypeIndex(type_ids, return_type_idx, string_ids, dex_file_begin);
                add_to_log("Return type in string " + return_type_string);


            }  
          
              
            let thread_pattern: any = thread.toMatchPattern();
            let matchList: MemoryScanMatch[] = Memory.scanSync(current_sp,2048, thread_pattern); 
            var i:number = 0;
            let code_compiled: Boolean = false; 
           
            // IN THE CASE ART IS EXECUTING NON COMPILED METHOD (IN THE PERFORM_CALL->INTERPRETER_TO_INTERPRETER
            // OR FROM THE JNI CALL TO_INTERPRETER_STUB->INTERPRETER_ENTRY_POINT) THE CODE_ITEM CONTAINING THE 
            // THE ARGUMENTS OFFSET IN THE SHADOW FRAME IS ON THE 
            // STACK AND WE CAN GET THE SHORTY FROM THE DEXCACHE OF THE METHOD
             
            //IN THE OTHER CASE (COMPILED CODE, NOT INTENDED TO BE DEBUGGED EVEN BY THE ART ITSELF) WE NEED TO 
            // FIND ANOTHER WAY KNOWING THAT THE PATH WILL BE 
            //PERFORM_CALL->TO_COMPILE_CODE->INVOKE->INSTRUMENTATION_STUB->..->PUSH_INSTRUMENTATION_STACK_FRAME->LISTENER
            //( NOT THE PATH   INVOKE->TO_COMPILE_CODE BECAUSE THIS ONE IS USED WHEN DEOPTIMIZE IS NOT ACTIVATED AND AN 
            // ALREADY COMPILED CODE SHOULD BE EXECUTED.)

            // FIRSTLY I WILL TEST IF IN THIS CASE I CAN GET THE SP IN STACK WHEN ART_INST_METHOD_ENTRY_FROM_CODE IS CALLED
            // TO OBTAIN ARGUMENTS
            // SECONDLY I WILL TEST IF I CAN ALSO OBTAIN THE SHORTY AS IN THE CASE ABOVE. (TO TEST FIRST)
            // TO LOCATE THIS SPECIAL CASE, I LOOK AT THE GENERAL VALUE OF THE I COUNTER AND STOP THE WHILE. ACCORDING TO IT
            //AFTER I WILL LOOK AT THE CALLER. 
            do { 
                let thread_stack_pointer: NativePointer = matchList[i].address;
                try{
                    if(i > 13){ /*IN THIS CASE, WE ARE SURE THAT WE ARE NO LONGER IN THE INTERPRETER CASE AS EXPLAINED ABOVE, BUT WE ARE 
                                  PROBABLY IN THE CASE WHERE THE METHOD IS COMPILED, SO WE BREAK AND RESTART THE LOOP TO IDENTIFY ARGUMENTS POINTERS 
                                  ON ANOTHER WAY AND POSSIBLY THE CALLER 
                                 following this rules in the quick_entry_point_x86.S
                              */
                        code_compiled = true; 
                        add_to_log("Probably we are with a compiled source code");
                        break;
                    }

                    let prospective_shadowFrame: NativePointer = Memory.readPointer(thread_stack_pointer.add(2*dword_size));
                    let prospective_method: NativePointer  = Memory.readPointer(prospective_shadowFrame.add(1*Process.pointerSize));
                    if(prospective_method.equals(this.method)){
                        let prospective_shadow_frame_code_item = Memory.readPointer(thread_stack_pointer.add(dword_size)); 
                        //log("Shadow frame code_item = " + prospective_shadow_frame_code_item);
                        let number_registers = Memory.readU16(prospective_shadow_frame_code_item);
                        let number_inputs = Memory.readU16(prospective_shadow_frame_code_item.add(2));
                        //log("number of registers = " + number_registers + " number of inputs " + number_inputs);
                        if(number_inputs <= number_registers){
                            //log(" //////////////start/////////////");
                            //log("Method: " + prospective_method);
                            add_to_log("Shadow frame :" + prospective_shadowFrame + " thread position " + i);
                            add_to_log("thread : " + thread);

                            /// GETTING THE CALLER NAME AND HIS ClASS NAME TO TEST..
                            // by direclyty looking inside the shadow frame, the caller is not avalaible see the code in the draft. 
                            // so I decided to look at the stack (second time)
                            // there are two cases in the interpreter; 
                            ///   1--- If we where already in the interpreter and we have been called by 
                            ///        docallCommon->PerformCall->ArtInterpreterToInterpreterBridge()
                            ///         this is an easy option to retrive the caller because it in the caller shadow frame, third parameter of the former function (performCall is inlined)
                            ///          the firsts parameters are thread and method (so adjacent on the stack,method is at k, and thread at k+1)
                            ///  2---- If we where not in the interpreter, we are jumping in it 
                            //            art_quick_to_interpreter_bridge->artQuickToInterpreterBridge->EnterInterpreterFromEntryPoint
                            //              but little complicated because not sure  if  the sp contains the caller. 
                            //  In the compile code (the second loop) The call is emulated when invoke_stub is called so the caller is null. 
                            //firstly I print the stack. 
                            ///  When looking at the stack the caller method in the case one is used when  the method is compiled PerformCall->artInterpreterToCompile. 
                            /// And as described in the paper, it is null. 
                            //scanMemory(thread_stack_pointer, 512);
                            //log(" method executions stack: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n\t"));
                            
                            while(i < matchList.length){
                                i++;
                                let new_thread_stack_pointer: NativePointer = matchList[i].address;
                                let new_prospective_method: NativePointer = Memory.readPointer(new_thread_stack_pointer.sub(dword_size));

                                if(this.method.equals(new_prospective_method)){
                                    add_to_log("bingo!!!!! ---> we reached the call docallCommon ");
                                    let caller_shadow_frame: NativePointer = Memory.readPointer(new_thread_stack_pointer.add(dword_size));
                                    add_to_log("caller shadow frame = " + caller_shadow_frame);
                                    let caller_method: NativePointer = Memory.readPointer(caller_shadow_frame.add(Process.pointerSize));
                                    add_to_log("caller method = " + caller_method);
                                    if(caller_method.isNull()) {
                                        add_to_log("caller method is null");
                                        //continue;
                                    }

                                }

                            }
                            if(i == matchList.length) add_to_log("cannot find doCall, the method is called probably by the Jni"); 
                         



                            let arg_offset: number = number_registers - number_inputs;
                            let shadow_frame_number_vregs: number = Memory.readU32(prospective_shadowFrame.add(24)); 
                            //log("number of vreg " + shadow_frame_number_vregs);
                            let shadow_frame_vregs_: NativePointer = (prospective_shadowFrame.add(36));
                            let args: NativePointer = shadow_frame_vregs_.add(arg_offset * Process.pointerSize);
                            let args_size: number = shadow_frame_number_vregs - arg_offset; 
                            add_to_log("----> args pointer = " + args + "\n-----> size = " + args_size);
                            //let result_register = Memory.readPointer(thread_stack_pointer.add(3*dword_size)); //because the biggest size of Jvalue is 4+4 bytes =2 * dword
                            //log("Result register  = " + result_register);
                            //let stay_in_interpreter = Memory.readInt(thread_stack_pointer.add(5*dword_size)); //because the biggest size of Jvalue is 4+4 bytes =2 * dword
                            //log("stay in interpreter = " + stay_in_interpreter);
                        }
                        break;
                    }else{
                        continue;
                    }
                } catch (error) {
                    //log("Error!" + error);
                }
            } while(++i < matchList.length);

            /// NOW PROCESSING THE CASE WHERE THE CODE IS COMPILED
            if(code_compiled){
                i = 0; add_to_log("---------------->The method code is probably compiled");
                do { 
                    let thread_stack_pointer: NativePointer = matchList[i].address;
                    try{
                       // IN THIS CASE, WE ARE SURE THAT WE ARE NO LONGER IN THE INTERPRETER CASE AS EXPLAINED ABOVE, BUT WE ARE 
                                    // PROBABLY IN THE CASE WHERE THE METHOD IS COMPILED, SO WE BREAK AND RESTART THE LOOP TO IDENTIFY ARGUMENTS POINTERS 
                                    // ON ANOTHER WAY AND POSSIBLY THE CALLER 
                                    // following this rules in the quick_entry_point_x86.S
                                    /*
                                    * Quick invocation stub (non-static).
                                    * On entry:
                                    *   [sp] = return address
                                    *   [sp + 4] = method pointer
                                    *   [sp + 8] = argument array or null for no argument methods
                                    *   [sp + 12] = size of argument array in bytes
                                    *   [sp + 16] = (managed) thread pointer
                                    *   [sp + 20] = JValue* result
                                    *   [sp + 24] = shorty
                                    */
                        /* If it is the correct one you will have 
                            --->sp
                            ---->thread
                            ---->object
                            ----->method*/
                        let prospective_object: NativePointer = Memory.readPointer(thread_stack_pointer.sub(dword_size));
                        let prospective_method: NativePointer  = Memory.readPointer(thread_stack_pointer.sub(2 * Process.pointerSize));
                        //log("-----> compiled code");
                        //log("Prospective object : " + prospective_object);
                        //log("Object : " + this.object);
                        //log("Prospective method: " + prospective_method + ", method: "+method);
                        add_to_log("-->this.method: " + this.method + " ---->prospective method: " + prospective_method + "thread stack pointer: " + thread_stack_pointer);
                        ///// THE TEST I WILL DO IS TRICKY, AN OPTION SHOULD BE TO ITERATE 8 TIMES BECAUSE I AM SURE TO HAVE THE STACK CORRESPONDING TO THE CALL   artInstMethodEntryFromCode
                        //BUT WHEN REVERSING THE ART ASM CODE OF quick_invoke_stub calling art_quick_inst_entry when invoking the method (the method quick code is replaced by the instrumenter)
                        // I NOTICED THAT THE STACK SHOULD HAVE A CERTAIN PATTERN (EXPLAINED IN THE PAPER): AT THE SP-POINTER_SIZE, THERE IS THE METHOD POINTER.
                        if(prospective_method.equals(this.method)){
                           
                            let SP: NativePointer = Memory.readPointer(thread_stack_pointer.add(dword_size));
                            if(Memory.readPointer(SP.sub(dword_size)).equals(method)){
                                add_to_log("Prospective object : " + prospective_object);
                                add_to_log("Object : " + this.object);
                                add_to_log("thread " + thread); 
                                add_to_log("Prospective method: " + prospective_method + ", method: "+method);
                                add_to_log("iteration " + i);
                                add_to_log("---------> Probably the good one");
                                //let SP_address: NativePointer = thread_stack_pointer.add(dword_size); 
                                let args: NativePointer = SP.add(17*dword_size); //This is wired I directly look at the stack pattern
                                if(shorty.length == 1){
                                    add_to_log(" arguments : no arguments to get");
                                }else{
                                    add_to_log(" arguments : " + args);
                                }      
                                break;
                            }/*else{
                                log("Bad warning");
                            }*/
                        }/*else{
                            log("---------> Not the good one");
                            //continue;
                        }*/
                    } catch (error) {
                        //log("Error!" + error);
                    }
                } while(++i < matchList.length);
            }


            //////// End of information retrieving
            var end = new Date().getTime();
            add_to_log("Call to doSomething took " + (end - start) + " milliseconds.")
            //userTraceCallbacks.onEnter(stringMethodName);
            //log(" method executions stack: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n\t"));

        },
        onLeave: function (retval) {
        }
      });

    return callback;
}

function scanMemory(address: NativePointer, numberBytes: number){
    add_to_log("----> scanning the memory from " + address + " to " + address.add(numberBytes));
    for(let i = numberBytes/Process.pointerSize; i >= 0; i--){
        add_to_log("-->address: " + address.add(i * Process.pointerSize) + ", value : " + Memory.readPointer(address.add(i * Process.pointerSize)));
    }
}

function makeMethodExited(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number, returnValue: NativePointer): void => {
        //log("MethodExited() thisObject=" + thisObject + " method=" + method + " JValue=" + returnValue);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32","pointer"]);
    retainedHandles.push(callback);
    return callback;
}

function makeListenerMethod(name: string): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer): void => {
        add_to_log(name + " was called!");
    }, "void", ["pointer", "pointer"]);
    retainedHandles.push(callback);

    return callback;
}

function makeFieldRead(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number, field: NativePointer): void => {
        add_to_log("FieldRead() thisObject=" + thisObject + " method=" + method+ " fieldObject="+field);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32","pointer"]);
    retainedHandles.push(callback);

    return callback;
}

function makeFieldWritten(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number, field: NativePointer, field_value: NativePointer): void => {
        add_to_log("FieldWritten() thisObject=" + thisObject + " method=" + method);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32","pointer","pointer"]);
    retainedHandles.push(callback);

    return callback;
}


//state of the stack
// arg1
// arg0
// retaddr
// ebp
// <---- esp
type ModuleHandle = NativePointer;
type DlopenFunc = (name: string) => ModuleHandle;
type DlsymFunc = (moduleHandle: ModuleHandle, name: string) => NativePointer;
function getDlopen(): DlopenFunc {
    /*if(Process.arch == "ia32"){
        return x86_tracer_tools.getDlopen();
    }*/
    const impl = Module.findExportByName(null, "dlopen");
    let cur = impl;
    let callsSeen = 0;
    let picValue: any = null;
    while (true) {
        const insn = Instruction.parse(cur);
        //log(insn.address + "  -->  " + insn.toString()); 

        switch (insn.mnemonic) {
            case "pop":
                if (insn.operands[0].value === "ebx") {
                    picValue = insn.address;
                }
                break;
            case "add":
                if (insn.operands[0].value === "ebx") {
                    picValue = picValue.add(insn.operands[1].value);
                }
                break;
            case "call":
                callsSeen++;
                if (callsSeen === 2) {
                    const innerDlopenImpl = ptr(insn.operands[0].value);
                    return makeDlopenWrapper(innerDlopenImpl, picValue); 
                }
                break;
        }
        cur = insn.next;
    }
}
function makeDlopenWrapper(innerDlopenImpl: NativePointer, picValue: NativePointer): DlopenFunc {
    const trampoline = Memory.alloc(Process.pageSize);
    Memory.patchCode(trampoline, 16, code => {
        const cw = new X86Writer(code, { pc: trampoline });
        cw.putMovRegAddress("ebx", picValue);
        cw.putJmpAddress(innerDlopenImpl);
        cw.flush();
    });

    const innerModifiedDlopen: any = new NativeFunction(trampoline, "pointer", ["pointer", "int", "pointer"]);
    const addressInsideLibc = Module.findExportByName("libc.so", "read");
    
    //innerDlopen.trampoline = trampoline;

    return function (path: string): NativePointer {
        const handle = innerModifiedDlopen(Memory.allocUtf8String(path), 3, addressInsideLibc);
        if (handle.isNull()) {
            const dlerror: any = new NativeFunction(Module.findExportByName(null, "dlerror") as NativePointer, "pointer", []);
            throw new Error("Unable to load helper: " + Memory.readUtf8String(dlerror()));
        }
        return handle;
    };
}
function getDlsym(): DlsymFunc {
    const dlsym: any = new NativeFunction(Module.findExportByName(null, "dlsym") as NativePointer, "pointer", ["pointer", "pointer"]);
    return function (moduleHandle: ModuleHandle, name: string): NativePointer {
        const address = dlsym(moduleHandle, Memory.allocUtf8String(name));
        if (address.isNull()) {
            throw new Error(`Symbol not found: ${name}`);
        }
        return address;
    };
}


/*/* struct ProtoId {
    dex::StringIndex shorty_idx_;     // index into string_ids array for shorty descriptor
    dex::TypeIndex return_type_idx_;  // index into type_ids array for return type
    uint16_t pad_;                    // padding = 0
    uint32_t parameters_off_;         // file offset to type_list for parameter types

   private:
    DISALLOW_COPY_AND_ASSIGN(ProtoId);
  };*/
function getProtoParameters(protoId: NativePointer, dex_file_begin: NativePointer): NativePointer{
    let result: NativePointer = NULL;
    let parameter_off_: number = Memory.readU32(protoId.add(8));
    if(parameter_off_ != 0){
        result = dex_file_begin.add(parameter_off_);
    }
    return result;
}
function getStringByTypeIndex(type_ids: NativePointer, type_index: number, string_ids: NativePointer, dex_file_begin: NativePointer): string | null{
    //log("-->in function getStringByTypeIndex");
    let type_id =  type_ids.add(type_index*4);
    let descriptor_idx: NativePointer = Memory.readPointer(type_id);
    let descriptor_string_offset =  Memory.readPointer(string_ids.add(descriptor_idx.shl(2)));
    let descriptor_string_address: NativePointer = dex_file_begin.add(descriptor_string_offset.add(1));
    let type_: any = Memory.readUtf8String(descriptor_string_address);
    if(type_.length == 1) return getPrimitiveTypeAsString(type_);
    return type_;
    //In the case we have one character, we need to make type readable 
}
function getPrimitiveTypeAsString(type: any): string|null{
        switch (type) {
            case 'B':
            return "Byte";
            case 'C':
            return "Char";
            case 'D':
            return "Double";
            case 'F':
            return "Float";
            case 'I':
            return "Int";
            case 'J':
            return "Long";
            case 'S':
            return "Short";
            case 'Z':
            return "Boolean";
            case 'V':
            return "Void";
            default:
            return "NotRecognised";
        } 
}
function printAsmExploreCallsGetShorty(impl: NativePointer, nlines: number): void{  
    let counter = 0;
    let cur: NativePointer = impl;
    let callsSeen = 0;
    let ebx: NativePointer = NULL;
    let innerFunction: NativePointer = NULL;
    while (counter < nlines) {    
        const insn = Instruction.parse(cur);
        add_to_log(insn.address + "-->  ......... " + insn.toString()); 
        switch (insn.mnemonic) {
            case "call":
                callsSeen++;
                if (callsSeen === 1){
                    add_to_log("computing the ebx value");
                    let eax = ptr(insn.operands[0].value);
                    add_to_log("eax will have " + eax);
                    ebx = eax.add(ptr("0x13f17")); 
                    add_to_log("and ebx =" + ebx);
                }if (callsSeen === 2) {
                    innerFunction = ptr(insn.operands[0].value);
                   
                }
                break;
        } 
        cur = insn.next;  
        counter++; 
        if(insn.mnemonic=="ret") break;
    }
    //log("------> start printing the inner function " + innerFunction);
    printAsm(innerFunction, 1000);
    //log("------> end printing the inner function " + innerFunction);

    let counter_ebx_function = 192;
    counter_ebx_function = counter_ebx_function + 4;
    while (counter_ebx_function <= 1220) {    
        //let dwordfromebx: NativePointer =  ebx.add(ptr(counter_ebx_function));
        //log("--------------> printing dword ptr [ebx + 0x" + counter_ebx_function.toString(16)  + " ]: ");
        printAsm(Memory.readPointer(ebx.add(ptr(counter_ebx_function))), 1000);
        //log("--------------> end printing  dword ptr [ebx + 0x" + counter_ebx_function.toString(16)  + " ]: ");
        counter_ebx_function = counter_ebx_function + 4;
    }

}

function printAsm(impl: NativePointer, nlines: number, force: boolean = false): void{  
    let counter = 0;
    let cur: NativePointer = impl;
    //log("---------------------------> printing the simple asm");
    while (counter < nlines) {    
        const insn = Instruction.parse(cur);
        //log(insn.address + "--> ......... " + insn.toString()); 
        //counter++;
        cur = insn.next;  
        counter++; 
        if(insn.mnemonic=="ret") break;
    }
    //log("----------------------------> end printing simple asm")
}


function patchInvoke(): void{
    Interceptor.attach(method_Invoke, {
        onEnter: function (args) {
            this.thread = args[1];
            this.args = args[2];
            
            //this.method = args[3];
            //log("invokef: called from: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n\t"));
            //log("MethodEntered()  from the Interceptor ---method=" + this.method + " context=" + JSON.stringify(this.context));
            //log("Loop from the stack pointer " +JSON.stringify(this.context));
            let current_sp = this.context.sp; 
            let dword_size = 4;
            //void ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size, JValue* result,const char* shorty)
            //--->shorty = sp+dword_size*6;
            //--->result = sp+dword_size*5;
            //--->args_size = sp+dword_size*4;
            //--->args = sp+dword_size*3;
            //--->thread = sp+dword_size*2;
            //--->method = sp+dword_size
            let thread: NativePointer = this.thread;
            this.method = Memory.readPointer(current_sp.add(dword_size));
            let args_ = Memory.readPointer(current_sp.add(dword_size*3));
            let methodNameStringObject = getNameAsString(this.method, thread); 
            const stringMethodName = getNameFromStringObject(methodNameStringObject,thread);
    
            //let args_size = Memory.readU32(current_sp.add(dword_size*4));
            //let current_args = Memory.readPointer(current_sp.add(dword_size*3));
            let prospective_shorty = Memory.readPointer(current_sp.add(dword_size*6));
            //log("---->shorty address = " + prospective_shorty + " thread  = " + this.thread + " args = " + this.args + " method = " + this.method + "-" + stringMethodName);
            add_to_log("---->invokef: called from: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n\t ---->"));

             //log(" first character = " + Memory.readUtf8String(prospective_shorty, 1)); 
            //log("this.threadId = " + this.threadId);
        },
        onLeave: function (retval) {
          //log("-----> Leaving the invoke callback thread = " + this.thread + "args = " + this.args + " method = " + this.method);
        }
      });
}

function patchAttachCurrentThread(): void{
    Interceptor.attach(runtimeAttachCurrentThread, {
        onEnter: function (args) {
            //log("---->invokef: called from: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n\t ---->"));
        },
        onLeave: function (retval) {
        }
      });
}



/*function printAsmExploreCallsGetShorty(impl: NativePointer, nlines: number): void{  
    let counter = 0;
    let cur: NativePointer = impl;
    let callsSeen = 0;
    let calledFunction: NativePointer = NULL; 
    let picValue: any = null;
    while (counter < nlines) {    
        const insn = Instruction.parse(cur);
        log(insn.address + "-->  ......... " + insn.toString()); 
        switch (insn.mnemonic) {
            case "call":
                callsSeen = callsSeen + 1;
                if(callsSeen == 2){
                    calledFunction = ptr(insn.operands[0].value);
                }    
        }
        cur = insn.next;  
        counter++; 
        if(insn.mnemonic=="ret") break;
    }
    printAsm(calledFunction,1000);
}*/



/*

// a bref easy to read code to descripbe how I obtained the shorty

 log("############### My attempt ");            
let proto_index_new: number = proto_index;
log("proto index new: " + proto_index_new);

let proto_id_new: NativePointer = proto_ids.add(proto_index_new * 12);
log("proto_id address new " + proto_id_new);
let shorty_idx_new: NativePointer =  Memory.readPointer(proto_id_new);
log("shorty_idx_new " + shorty_idx_new);



let prototype_string_offset_new: NativePointer = Memory.readPointer(string_ids.add(shorty_idx_new.shl(2)));
log("prototype_string offsett new " + prototype_string_offset_new);

if(Memory.readPointer(dex_file_begin.add(prototype_string_offset_new)).equals(NULL)) log("****error in getting the shorty"); 
let prototype_string_address_new: NativePointer = dex_file_begin.add(prototype_string_offset_new.add(1));
log("prototype_string_address : " + prototype_string_address_new);
log(" first character = " + Memory.readUtf8String(prototype_string_address_new)); 
                            

function called when exploring the getShorty code from a method call. 

function printAsmFirstJump(impl: NativePointer, ebx: NativePointer, nlines: number): void{  
    let counter = 0;
    let cur: NativePointer = impl;
    let jmpsSeen = 0;
    let picValue: any = null;
    let innerFunction1: NativePointer = NULL;
    while (counter < nlines) {    
        const insn = Instruction.parse(cur);
        log(insn.address + "-->  ......... " + insn.toString()); 
        switch (insn.mnemonic) {
            case "jmp":
                jmpsSeen++;
                if (jmpsSeen === 2) {
                    innerFunction1 = ptr(insn.operands[0].value);
                }
                break;       
        }
        cur = insn.next;  
        counter++; 
        if(insn.mnemonic=="ret") break;
    }
    
    log("------> start printing the inner jmp function " + innerFunction1);
    printAsm(innerFunction1, 1000);
    log("------> end printing the inner jmp function " + innerFunction1); 

    let counter_ebx_function = 28;

    let number_ = 12;
    //let dwordfromebx: NativePointer =  ebx.add(ptr(eigth));
    log("--------------> printing dword ptr [ebx + 0x" + number_.toString(16)  + " ]: ");
    let add = Memory.readPointer(ebx.add(ptr(number_))); log("address of code: " + add);
    printAsm(add, 1000);
    log("--------------> end printing  dword ptr [ebx + 0x" + number_.toString(16)  + " ]: ");
    counter_ebx_function = counter_ebx_function + 4;
    while (counter_ebx_function <= 1220) {    
        //let dwordfromebx: NativePointer =  ebx.add(ptr(counter_ebx_function));
        log("--------------> printing dword ptr [ebx + 0x" + counter_ebx_function.toString(16)  + " ]: ");
        printAsm(Memory.readPointer(ebx.add(ptr(counter_ebx_function))), 1000);
        log("--------------> end printing  dword ptr [ebx + 0x" + counter_ebx_function.toString(16)  + " ]: ");
        counter_ebx_function = counter_ebx_function + 4;
    }
}
function printAsmExploreEverything(impl: NativePointer, nlines: number): void{  
    let counter = 0;
    let cur: NativePointer = impl;
    //let callsSeen = 0;
    let picValue: any = null;
    while (counter < nlines) {    
        const insn = Instruction.parse(cur);
        log(insn.address + "-->  ......... " + insn.toString()); 
        switch (insn.mnemonic) {
            case "call":
                const innerFunction = ptr(insn.operands[0].value);
                log("------> start printing the inner function " + innerFunction);
                printAsm(innerFunction,1000);
                log("------> end printing the inner function " + innerFunction);
                break;
        }
        cur = insn.next;  
        counter++; 
        if(insn.mnemonic=="ret") break;
    }
}
function printAsmExploreShorty(impl: NativePointer, nlines: number): void{  
    let counter = 0;
    let cur: NativePointer = impl;GetMethodId
    let callsSeen = 0;
    let ebx: NativePointer = NULL;
    let innerFunction: NativePointer = NULL;
    while (counter < nlines) {    
        const insn = Instruction.parse(cur);
        log(insn.address + "-->  ......... " + insn.toString()); 
        switch (insn.mnemonic) {
            case "call":
                callsSeen++;
                if (callsSeen === 1){
                    log("computing the ebx value");
                    let eax = ptr(insn.operands[0].value);
                    log("eax will have " + eax);
                    ebx = eax.add(ptr("0x15298")); 
                    log("and ebx =" + ebx);
                }if (callsSeen === 2) {
                    innerFunction = ptr(insn.operands[0].value);
                   
                }
                break;
        }
        cur = insn.next;  
        counter++; 
        if(insn.mnemonic=="ret") break;
    }
    log("------> start printing the inner function " + innerFunction);
    printAsmFirstJump(innerFunction, ebx, 1000);
    log("------> end printing the inner function " + innerFunction);
}
old helper an attempts 
---------------------> added inside the interceptor to get args from invoke params but did not work 
if(!invoke_attached){
    patchInvoke(); invoke_attached = 1;
}
// Now I will try to get the shorty from the stack knowing that at this point (execute) an invoke() method has 
// already been called
//void ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size, JValue* result,const char* shorty)
//  example : method->Invoke(self, shadow_frame->GetVRegArgs(arg_offset),
//                     (shadow_frame->NumberOfVRegs() - arg_offset) * sizeof(uint32_t),result,
//                         method->GetInterfaceMethodIfProxy(kRuntimePointerSize)->GetShorty());
// I plan to continue analysing the stack frame (the matching list) to see if it is like 
//--->the potential shorty at (thread_stack_pointer + 4 * dword_size) contains ???    ;
//--->the potential result at (thread_stack_pointer + 3 * dword_size) contains  result register ;
//--->the potential args_size  at (thread_stack_pointer + 2 * dword_size) contains args_size*Process.pointerSize;
//--->the potential args at (thread_stack_pointer + dword_size) contains shadow_frame_vregs_ + arg_offset;
//--->the potential thread at the current_thread_match already contains readPointer(thread_stack_pointer)
do { 
    let current_thread_stack_pointer: NativePointer = matchList[i].address;
    //log("before the try  current address" + current_thread_stack_pointer);
    try{
        //log("in the try");
        let prospective_method_shorty: NativePointer = Memory.readPointer(current_thread_stack_pointer.sub(dword_size));
        let prospective_args_shorty: NativePointer = Memory.readPointer(current_thread_stack_pointer.add(dword_size));
        if(prospective_method_shorty.equals(prospective_method)){
            //log(" Bingo_Method + args " + prospective_args_shorty); 
            let prospective_shorty: NativePointer = Memory.readPointer(current_thread_stack_pointer.add(4 * dword_size));
            //log(" shorty " + prospective_shorty);
            //log("near to method invoke " + method_Invoke.sub(Memory.readPointer(current_thread_stack_pointer.sub(2 * dword_size))));
            //log(" first character = " + Memory.readUtf8String(prospective_shorty, 1));
            break;
        }  
        
        log("prospective args shorty " + prospective_args_shorty + " method " + prospective_method_shorty);
        if(prospective_args_shorty.equals(args)){
            log("looking for shorty, args are correct");
            let prospective_args_size_shorty: number = Memory.readU32(current_thread_stack_pointer.add(2 * dword_size));
            if(prospective_args_size_shorty == args_size){
                log("looking for shorty, args_size matching");
                let prospective_result_shorty: NativePointer = Memory.readPointer(current_thread_stack_pointer.add(3 * dword_size));
                if(prospective_result_shorty.equals(result_register)){
                    log("looking for shorty, result matching");
                    let shorty: NativePointer =  Memory.readPointer(current_thread_stack_pointer.add(4 * dword_size));
                    log(" Bingo_bingo ! shorty = " + shorty)
                    break;
                }
            }
        }
    } catch (error) {
        log("Error shorty!");
    }   
} while(++i<matchList.length); 

---------------------> trying to get the args from the invoke call, but finally the thread stack showed that it is called before 
function patchInvoke(): void{
    Interceptor.attach(method_Invoke, {
        onEnter: function (args) {
            this.thread = args[1];
            this.args = args[2];
            
            //this.method = args[3];
            //log("invokef: called from: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n\t"));
            //log("MethodEntered()  from the Interceptor ---method=" + this.method + " context=" + JSON.stringify(this.context));
            //log("Loop from the stack pointer " +JSON.stringify(this.context));
            let current_sp = this.context.sp; 
            let dword_size = 4;
            //void ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size, JValue* result,const char* shorty)
            //--->shorty = sp+dword_size*6;
            //--->result = sp+dword_size*5;
            //--->args_size = sp+dword_size*4;
            //--->args = sp+dword_size*3;
            //--->thread = sp+dword_size*2;
            //--->method = sp+dword_size
            let thread: NativePointer = this.thread;
            this.method = Memory.readPointer(current_sp.add(dword_size));
            let args_ = Memory.readPointer(current_sp.add(dword_size*3));
            let methodNameStringObject = getNameAsString(this.method, thread); 
            const stringMethodName = getNameFromStringObject(methodNameStringObject,thread);
    
            //let args_size = Memory.readU32(current_sp.add(dword_size*4));
            //let current_args = Memory.readPointer(current_sp.add(dword_size*3));
            let prospective_shorty = Memory.readPointer(current_sp.add(dword_size*6));
            //log("---->shorty address = " + prospective_shorty + " thread  = " + this.thread + " args = " + this.args + " method = " + this.method + "-" + stringMethodName);
            //log("---->invokef: called from: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n\t ---->"));

             //log(" first character = " + Memory.readUtf8String(prospective_shorty, 1)); 
            //log("this.threadId = " + this.threadId);
        },
        onLeave: function (retval) {
          //log("-----> Leaving the invoke callback thread = " + this.thread + "args = " + this.args + " method = " + this.method);
        }
      });
}

--------------------->  printing offsets
//const getOffsetOfShadowFrameDexPc: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_shadow_frame_dex_pc_"), "uint", []);
//log("helper think dex_pc is at offset " + getOffsetOfShadowFrameDexPc());
//const getOffsetOfShadowFrameDexPcPtr: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_shadow_frame_dex_pc_ptr_"), "uint", []);
//log("helper think dex_pc_ptr is at offset " + getOffsetOfShadowFrameDexPcPtr());
//const getJitActivated: any = new NativeFunction(dlsym(helper, "ath_get_jit_activated"), "uint", ["pointer"]);
//log("helper think jit activation is  " + getJitActivated(runtime)); //memory_order_relaxed
//const getMemoryOrderRelaxed: any = new NativeFunction(dlsym(helper, "ath_get_memory_order_relaxed"), "uint", []);
//log("helper think memory_order_relaxed is  " + getMemoryOrderRelaxed());
const getCodeItemOffsetOfInsSize: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_code_item_ins_size_"), "uint", []);
//log("helper think offset of ins is  " + getCodeItemOffsetOfInsSize());
const getMethodAccessFlag: any = new NativeFunction(dlsym(helper, "ath_get_method_field_"), "uint", []);
//log("helper think offset of fied is  " + getMethodAccessFlag());
const getShadowFrameOffsetOfVregs: any = new NativeFunction(dlsym(helper, "ath_get_shadow_frame_vregs_"), "uint", []); 
//log("helper think offset of vregs  " + getShadowFrameOffsetOfVregs());
const method_Invoke: any = new NativeFunction(
    dlsym(artlib,"_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc"),
    "void",
    ["pointer","pointer","uint32","pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
log("printing the address of  checkJni:CheckMethodAndSig " + method_Invoke);

----------------------->attempt to print asm code from function pointer of inlined methods (do not work) 
//const getShortyMethodAddress: any = new NativeFunction(dlsym(helper, "ath_get_shorty_address"), "pointer", []);
//log("getting the shorty address " + getShortyMethodAddress);
//printAsm(getShortyMethodAddress,1000);
//const getInterfaceMethodIfProxyAddress: any = new NativeFunction(dlsym(helper, "ath_get_interface_if_proxy_address"), "pointer", ["pointer"]);
//log("getting the getInterfaceMethodIfproxy address " + getInterfaceMethodIfProxyAddress);
//printAsm(getInterfaceMethodIfProxyAddress,1000);

----------------------> attempt to print asm of function calling getShorty or getInterfaceMethodIfProxy
const artQuickToInterpreterBridge: any = new NativeFunction(
    dlsym(artlib,"artQuickToInterpreterBridge"),
    "uint64",
    ["pointer","pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
});
log("###########printing the address of  artQuickToInterpreterBridge " + artQuickToInterpreterBridge);
const ExecuteMterpImpl: any = new NativeFunction(
dlsym(artlib,"ExecuteMterpImpl"),
"bool",
["pointer","pointer","pointer","pointer"],
{
    exceptions: ExceptionsBehavior.Propagate
});
log("printing the address of  ExecuteMterpImpl " + ExecuteMterpImpl);
printAsm(ExecuteMterpImpl, 1000);
const checkVarArgs: any = new NativeFunction(
    dlsym(artlib,"_ZN3art11ScopedCheck12CheckVarArgsERNS_18ScopedObjectAccessEPKNS_7VarArgsE"),
    "bool",
    ["pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
log("printing the address of  checkVarArgs " + checkVarArgs);
printAsm(checkVarArgs, 100000);
const ArtInterpreterToCompiledCodeBridge: any = new NativeFunction(
    dlsym(artlib,"_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_11ShadowFrameEtPNS_6JValueE"),
    "bool",
    ["pointer","pointer","pointer","uint16","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
log("printing the address of  ArtInterpreterToCompiledCodeBridge " + ArtInterpreterToCompiledCodeBridge);
printAsm(ArtInterpreterToCompiledCodeBridge, 100000);
_ZN3art11ScopedCheck12CheckVarArgsERNS_18ScopedObjectAccessEPKNS_7VarArgsE
const checkJni_CheckMethodAndSig: any = new NativeFunction(
    dlsym(artlib,"_ZN3art11ScopedCheck17CheckMethodAndSigERNS_18ScopedObjectAccessEP8_jobjectP7_jclassP10_jmethodIDNS_9Primitive4TypeENS_10InvokeTypeE"),
    "bool",
    ["pointer","pointer","pointer","pointer","uint32","uint32"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
log("printing the address of  checkJni:CheckMethodAndSig " + checkJni_CheckMethodAndSig);
printAsm(checkJni_CheckMethodAndSig, 1000);
const gdb_OutputMethodReturnValue: any = new NativeFunction(
    dlsym(artlib,"_ZN3art3Dbg23OutputMethodReturnValueEyPKNS_6JValueEPNS_4JDWP9ExpandBufE"),
    "void",
    ["uint64","pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
log("printing the address of gdb::OutputMethodReturnValue " + gdb_OutputMethodReturnValue);
log("code : \n ");
printAsm(gdb_OutputMethodReturnValue, 1000);
const Executable_CreateFromArtMethod: any = new NativeFunction(
    dlsym(artlib,"_ZN3art6mirror10Executable19CreateFromArtMethodILNS_11PointerSizeE4ELb1EEEbPNS_9ArtMethodE"),
    "bool",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
log("printing the address of  Executable::CreateFromArtMethod " + Executable_CreateFromArtMethod);
log("code : \n ");
printAsm(Executable_CreateFromArtMethod, 1000);
const trace_GetMethodLine : any = new NativeFunction(
    dlsym(artlib,"_ZN3art5Trace13GetMethodLineEPNS_9ArtMethodE"),
    "pointer",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
log("printing the address of  Trace::GetMethodLine " + trace_GetMethodLine);
log("code : \n ");
printAsm(trace_GetMethodLine, 1000);  
const classLinker_SetIMTRef  : any = new NativeFunction(
    dlsym(artlib,"_ZN3art11ClassLinker9SetIMTRefEPNS_9ArtMethodES2_S2_PbPS2_"),
    "pointer",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
log("printing the address of  classLinker_SetIMTRef" + classLinker_SetIMTRef);
log("code : \n ");
printAsm(classLinker_SetIMTRef, 1000);

-------------------------> some other helper code 
log(" -- forced_interpret_only_ value is : " + Memory.readS8(instrumentation.add(Process.pointerSize)) );
log(" -- deoptimization_enabled value is : " + Memory.readS8(instrumentation.add(203)) );
let i = 0
for (i = 0; i<= 216 ; i++){
    if (Memory.readS8(instrumentation.add(216-i)) == 0 || Memory.readS8(instrumentation.add(216-i)) == 1)
    {log("boolean offset : " + (216-i) + "value : " + Memory.readS8(instrumentation.add(216-i)));}
} 
    HELPER CODE
        log("preparing and call deoptimization");
        const prepareDoptimization: any = new NativeFunction(
        dlsym(helper, "ath_prepare_call_deoptimisation"), 
        "pointer", 
        ["pointer","pointer","pointer"]
        ,{
            exceptions: ExceptionsBehavior.Propagate
     });
     /log(`helper module: ${helper.toString()}`);
        /*const getOffsetOfRuntimeInstrumentation: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_runtime_instrumentation"), "uint", []);
        log("we think instrumentation is at offset " + instrumentationOffset + ", helper thinks it's at " + getOffsetOfRuntimeInstrumentation());    
        
        const getOffsetOfClassIftable: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_class_iftable_"), "uint", []);
        log("we think  types ids is at offset " + 16 + ", helper thinks it's at " + getOffsetOfClassIftable());    
        */

        
        //const getMethoyTryCallShorty: any = new NativeFunction(dlsym(helper, "ath_get_method_try_call_shorty"), "pointer", ["pointer"]);
        //log("///////looking inside the getShorty() source code");
        //printAsmExploreShorty(getMethoyTryCallShorty, 1000);
        //const getMethoyTryCallGetInterfaceIfProxy: any = new NativeFunction(dlsym(helper, "ath_get_method_try_call_get_interface_if_proxy"), "pointer", ["pointer"]);
        //log("helper think ath_get_method_try_call_shorty is  " + getMethoyTryCallShorty());
        //log("getInterfaceMethodIfProxy()");
        //printAsmExploreShorty(getMethoyTryCallGetInterfaceIfProxy, 1000);
        //const getMethodShorty: any = new NativeFunction(dlsym(helper, "ath_get_method_shorty_"), "pointer", ["pointer"]);
        /*log("method Shorty code ");
        printAsm(getMethodShorty, 1000);*/
        /*const helperGetShorty: any = new NativeFunction(
        dlsym(helper,"_ZN3art9ArtMethod9GetShortyEv"),
        "pointer",
        [],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
        log("address of getShorty in the helper" + helperGetShorty);*/
        //printAsmExploreCallsGetShorty(helperGetShorty,1000)
       
       //log("address of runtimeAttachCurrentThread in the helper" + runtimeAttachCurrentThread);
        //printAsmExploreCallsGetShorty(helperGetShorty,1000)
    
    
        /*const mirror_FindDeclaredDirectMethodByName: any = new NativeFunction(
        dlsym(artlib,"_ZN3art6mirror5Class30FindDeclaredDirectMethodByNameERKNS_11StringPieceENS_11PointerSizeE"),
        "pointer",
        ["pointer","pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
        log("printing the address of mirror_FindDeclaredDirectMethodByName " + mirror_FindDeclaredDirectMethodByName);
        log("code : \n ");
        printAsm(mirror_FindDeclaredDirectMethodByName, 1000);*/

        /*const instrumentationListener_MethodExited: any = new NativeFunction(
        dlsym(artlib,"_ZN3art15instrumentation23InstrumentationListener12MethodExitedEPNS_6ThreadENS_6HandleINS_6mirror6ObjectEEEPNS_9ArtMethodEjS7_"),
        "void",
        ["pointer","pointer","pointer","uint32","pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
        log("printing the address of instrumentationListener_MethodExited " + instrumentationListener_MethodExited);
        log("code : \n ");
        printAsm(instrumentationListener_MethodExited, 1000);
    
        const trace_GetMethodLine: any = new NativeFunction(
        dlsym(artlib,"_ZN3art5Trace13GetMethodLineEPNS_9ArtMethodE"),
        "pointer",
        ["pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
        log("printing the address of Trace::GetMethodLine " + trace_GetMethodLine);
        log("code : \n ");
        printAsm(trace_GetMethodLine, 1000);
-----------------------> modification needed to activate the deoptimization directly in the app config
to test in app <application
android:icon="@mipmap/ic_launcher"
android:label="@string/app_name"
android:vmSafeMode="true">

------------------------> some codes used to test the deoptimization enabling before finally using java.perform
const myForceInterpretOnly: any = new NativeFunction(dlsym(helper, "ath_instrumentation_force_interpret_only"), "void", ["pointer"]);
log("before force_interpret_only_call");
let i = 0;
for (i = 0; i<= 216 ; i++){
    if (Memory.readS8(instrumentation.add(216-i)) == 0 || Memory.readS8(instrumentation.add(216-i)) == 1)
    {log("boolean offset : " + (216-i) + "value : " + Memory.readS8(instrumentation.add(216-i)));}
}
myForceInterpretOnly(instrumentation);
log("after force_interpret_only_call");
for (i = 0; i<= 216 ; i++){
    if (Memory.readS8(instrumentation.add(216-i)) == 0 || Memory.readS8(instrumentation.add(216-i)) == 1)
    {log("boolean offset : " + (216-i) + "value : " + Memory.readS8(instrumentation.add(216-i)));}
}

-------------------------> useful mangled function to manipulate the scope
"_ZN3art2gc23ScopedGCCriticalSectionD1Ev",
    "_ZN3art2gc23ScopedGCCriticalSectionD2Ev",
    "_ZN3art2gc23ScopedGCCriticalSectionC2EPNS_6ThreadENS0_7GcCauseENS0_13CollectorTypeE",
    "_ZN3art2gc23ScopedGCCriticalSectionC1EPNS_6ThreadENS0_7GcCauseENS0_13CollectorTypeE"

-----------------------> log related to the shadow frame processing in the function Interpreter::Execute()    
let address_in_execute = Memory.readPointer(thread_stack_pointer.sub(dword_size));
log("address in execute " + address_in_execute);
log("Patching the invoke");

-----------------------> code of dlopen used to create the trampoline
                                                            push ebp
02-27 10:58:10.617  7144  7144 I frida   : 0xf1bd0ef1  -->  mov ebp, esp
02-27 10:58:10.617  7144  7144 I frida   : 0xf1bd0ef3  -->  push ebx
02-27 10:58:10.617  7144  7144 I frida   : 0xf1bd0ef4  -->  and esp, 0xfffffff0
02-27 10:58:10.617  7144  7144 I frida   : 0xf1bd0ef7  -->  sub esp, 0x10
02-27 10:58:10.617  7144  7144 I frida   : 0xf1bd0efa  -->  call 0xf1bd0eff
02-27 10:58:10.617  7144  7144 I frida   : 0xf1bd0eff  -->  pop ebx
02-27 10:58:10.617  7144  7144 I frida   : 0xf1bd0f00  -->  add ebx, 0x20a1
02-27 10:58:10.618  7144  7144 I frida   : 0xf1bd0f06  -->  sub esp, 4
02-27 10:58:10.618  7144  7144 I frida   : 0xf1bd0f09  -->  push dword ptr [ebp + 4]
02-27 10:58:10.618  7144  7144 I frida   : 0xf1bd0f0c  -->  push dword ptr [ebp + 0xc]
02-27 10:58:10.618  7144  7144 I frida   : 0xf1bd0f0f  -->  push dword ptr [ebp + 8]
02-27 10:58:10.618  7144  7144 I frida   : 0xf1bd0f12  -->  call 0xf1bd0d10
02-27 10:58:10.626  7144  7144 I frida   : 0xf1bd0f17  -->  add esp, 0x10
02-27 10:58:10.626  7144  7144 I frida   : 0xf1bd0f1a  -->  lea esp, [ebp - 4]
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f1d  -->  pop ebx
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f1e  -->  pop ebp
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f1f  -->  ret   ----
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f20  -->  push ebp
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f21  -->  mov ebp, esp
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f23  -->  push ebx
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f24  -->  and esp, 0xfffffff0
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f27  -->  sub esp, 0x10
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f2a  -->  call 0xf1bd0f2f
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f2f  -->  pop ebx
02-27 10:58:10.628  7144  7144 I frida   : 0xf1bd0f30  -->  add ebx, 0x2071
02-27 10:58:10.628  7144  7144 I frida   : 0xf1bd0f36  -->  call 0xf1bd0d20
02-27 10:58:10.628  7144  7144 I frida   : 0xf1bd0f3b  -->  lea esp, [ebp - 4]
02-27 10:58:10.628  7144  7144 I frida   : 0xf1bd0f3e  -->  pop ebx
02-27 10:58:10.628  7144  7144 I frida   : 0xf1bd0f3f  -->  pop ebp
02-27 10:58:10.628  7144  7144 I frida   : 0xf1bd0f40  -->  ret
02-27 10:58:10.628  7144  7144 I frida   : 0xf1bd0f41  -->  jmp 0xf1bd0f50
02-27 10:58:10.628  7144  7144 I frida   : 0xf1bd0f43  -->  nop

------------------------> first attemps to get the current stack
// I will use the managed stack (offset 140 of the thread Object)
let managed_stack  = thread.add(140);
log("---Managed stack=" + managed_stack);       
// try to access the shadow stack (it is private but we don't care??? Ole answer)
let shadow_frame_from_managed_stack = Memory.readPointer(managed_stack.add(2 * Process.pointerSize));
log("-Shadow frame from managed stack =" + shadow_frame_from_managed_stack);
let art_method_0 = shadow_frame_from_managed_stack.isNull() ? new NativePointer(0) : Memory.readPointer(shadow_frame_from_managed_stack.add(1*Process.pointerSize));
log("-corresponding method =" + art_method_0);
    //just to test offset
let dex_pc_ptr_val_managed_stack= shadow_frame_from_managed_stack.isNull() ? null : Memory.readU32(shadow_frame_from_managed_stack.add(4*Process.pointerSize));
log("dex_pc =" + dex_pc_ptr_val_managed_stack);
//just test the method
if(!art_method_0.isNull()) log("-/testing this method : (dex_method_index_) " +  Memory.readU32(art_method_0.add(8)));
let top_quick_frame_add = Memory.readPointer(managed_stack);  
log("-Top quick frame from managed stack =" + top_quick_frame_add);
let art_method_1 = top_quick_frame_add.isNull() ? new NativePointer(0) : Memory.readPointer(top_quick_frame_add);
log("-Corresponding method : " + art_method_1); /// because the quick frame contains pointer to methods. 
//just test the method
if(!art_method_1.isNull()) log("-/testing this method : (dex_method_index_) " +  Memory.readU32(art_method_1.add(8)));
// We can also use the instrumentation stack *
let instrumentation_stack = Memory.readPointer(thread.add(208));
log("-Instrumentation stack handle=" + instrumentation_stack);
let instrumentationStack : StdInstrumentationStackDeque = new StdInstrumentationStackDeque(instrumentation_stack);
let front_frame = instrumentationStack.front();
log("-----front frame of the instrumentation stack = " + front_frame);
let art_method_front =  front_frame.isNull() ? new NativePointer(0) : Memory.readPointer(front_frame.add(1 * Process.pointerSize));
log("-Corresponding method : " + art_method_front);
//just to test offset
let interpreter_entry_front= front_frame.isNull() ? null : Memory.readInt(front_frame.add(16));
log("interpreter_entry_ =" + interpreter_entry_front);
//just test the method
if(!art_method_front.isNull()) log("-/testing this method : (dex_method_index_)" +  Memory.readU32(art_method_front.add(8)));
let back_frame = instrumentationStack.back();
log("-----back frame of the instrumentation stack = " + back_frame);
let art_method_back =  back_frame.isNull() ? new NativePointer(0) : Memory.readPointer(back_frame.add(1 * Process.pointerSize));
log("-Corresponding method : " + art_method_back);
//just to test offset
let interpreter_entry_back= back_frame.isNull() ? null : Memory.readInt(back_frame.add(16));
log("interpreter_entry_ =" + interpreter_entry_back);
//just test the method
if(!art_method_back.isNull()) log("-/testing this method : (dex_method_index_)" +  Memory.readU32(art_method_back.add(8)));  

-----------------------> method used to process the libc array
end(): NativePointer {
// defined at line 1086 https://github.com/llvm-mirror/libcxx/blob/master/include/deque
// we ignore the iterator 
// supposing that the second arg of __mp it contains the address of the element we want 
// (it second is the one retrived when referencing the iterator at line 318)
this.refresh();
log("---  we get the end"); 
let __p : number = this.size() + this.__start_;
log(" value of p " + __p); 
let  __mp : NativePointer = this.__map_begin().add(  Math.floor(__p / this.__block_size)) ;
log (" processing the __mp : " + __mp + " with ratio p/size : " +  Math.floor(__p / this.__block_size)
                            + " p%size = " + __p % this.__block_size);
let result : NativePointer = this.__map_empty() ? 
                                new NativePointer(0) :
                                Memory.readPointer(__mp).add((__p % this.__block_size));
log("final result " + result );
return result;
}


------------------------------> // by direclyty looking inside the shadow frame, the caller is not avalaible see the code in the draft. 
                            let link_shadow_frame: NativePointer = Memory.readPointer(prospective_shadowFrame);
                            if(link_shadow_frame.isNull){
                                log("caller name is not avalaible");
                            }else{
                                log("caller shadow frame address " + link_shadow_frame);
                                let link_method: NativePointer = Memory.readPointer(link_shadow_frame.add(1*Process.pointerSize));
                                let linkMethodNameStringObject = getNameAsString(link_method, thread); 
                                const stringLinkMethodName = getNameFromStringObject(linkMethodNameStringObject,thread);
                                log("caller Method : " + stringLinkMethodName);

                                let rawLinkClassName: string;
                                const storage = new StdString();
                                const link_declaring_classHandle= link_method.add(declaringClassOffset);
                                const link_declaring_class_ = ptr(Memory.readU32(link_declaring_classHandle));
                                rawLinkClassName = Memory.readUtf8String(getDescriptor(link_declaring_class_, storage)) as string;   
                                storage.dispose();
                                const link_className = rawLinkClassName.substring(1, rawLinkClassName.length - 1).replace(/\//g, ".");
                                log("caller class Name" + link_className);
                            }


*/
