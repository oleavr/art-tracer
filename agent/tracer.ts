import * as Java from "frida-java";
import { getApi } from "frida-java/lib/android";
import { getArtThreadFromEnv } from "frida-java/lib/android";
import { log } from "./logger";
import  VM  from "frida-java/lib/vm"
import { prototype } from "stream";
import { print } from "util";
const api = getApi();


export interface TraceCallbacks {
    onEnter(methodName: string): void;
    onLeave(methodName: string): void;
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

let invoke_attached: number = 0;

let listener: NativePointer;
try {
    listener = makeListener();
} catch (e) {
    log("Shit: " + e.stack);
}

const runtime = api.artRuntime;
const dlopen = getDlopen();
const dlsym = getDlsym();
const artlib : any = dlopen("/system/lib/libart.so");
const libcpp : any = dlopen("/system/lib/libc++.so");

// HELPER CODE
const helperPath = "/data/local/tmp/re.frida.server/libart-tracer-helper.so";
const helper : any = dlopen(helperPath);
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



    
export function trace(callbacks: TraceCallbacks) {
    Java.perform(() => {
        log("trace() starting up");
     
        const vm = new VM(api);
        const instrumentationOffset = 464;
        const instrumentation = runtime.add(instrumentationOffset);
        
        // HELPER CODE
        //log(`helper module: ${helper.toString()}`);
        const getOffsetOfRuntimeInstrumentation: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_runtime_instrumentation"), "uint", []);
        log("we think instrumentation is at offset " + instrumentationOffset + ", helper thinks it's at " + getOffsetOfRuntimeInstrumentation());    
        
        const getOffsetOfClassIftable: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_class_iftable_"), "uint", []);
        log("we think instrumentation is at offset " + 16 + ", helper thinks it's at " + getOffsetOfClassIftable());    


        
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

      

        
        
        const mirror_FindDeclaredDirectMethodByName: any = new NativeFunction(
        dlsym(artlib,"_ZN3art6mirror5Class30FindDeclaredDirectMethodByNameERKNS_11StringPieceENS_11PointerSizeE"),
        "pointer",
        ["pointer","pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
        log("printing the address of mirror_FindDeclaredDirectMethodByName " + mirror_FindDeclaredDirectMethodByName);
        log("code : \n ");
        printAsm(mirror_FindDeclaredDirectMethodByName, 1000);

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
        printAsm(trace_GetMethodLine, 1000);*/

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
            dlsym(helper,"_ZN3art15instrumentation15Instrumentation11AddListenerEPNS0_23InstrumentationListenerEj"),
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
        // HELPER CODE
        //log("preparing and call deoptimization");
        const prepareDoptimization: any = new NativeFunction(
        dlsym(helper, "ath_prepare_call_deoptimisation"), 
        "pointer", 
        ["pointer","pointer","pointer"]
        ,{
            exceptions: ExceptionsBehavior.Propagate
        });
        const env = vm.getEnv();
        const threadHandle = getArtThreadFromEnv(env);
        //prepareDoptimization(instrumentation, Memory.allocUtf8String("frida"),threadHandle);
        deoptimizeEverything(instrumentation, Memory.allocUtf8String("frida"));
        addListener(instrumentation, listener, InstrumentationEvent.MethodEntered /* | InstrumentationEvent.MethodExited | InstrumentationEvent.FieldRead | InstrumentationEvent.FieldWritten*/);
        //log("--------> after api: " + JSON.stringify(api));    
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
        let methodNameStringObject = getNameAsString(method, thread); 
        const stringMethodName = getNameFromStringObject(methodNameStringObject,thread);
        /// GETTING THE CLASS NAME : APPROACH BY METHOD CLASS 
        let declaringClassOffset = 0;
        const declaring_classHandle= method.add(declaringClassOffset);
        const declaring_class_ = ptr(Memory.readU32(declaring_classHandle));
        /// TRYING WITH THE DESCRIPTOR    const char* Class::GetDescriptor(std::string* storage)
        const getDescriptor: any = new NativeFunction(
            dlsym(artlib,"_ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE") as NativePointer,
            "pointer",
            ["pointer","pointer"],
            {
                exceptions: ExceptionsBehavior.Propagate
            });

        let rawClassName: string;
        const storage = new StdString();
        rawClassName = Memory.readUtf8String(getDescriptor(declaring_class_, storage)) as string;   
        storage.dispose();
        const className = rawClassName.substring(1, rawClassName.length - 1).replace(/\//g, ".");
        log("///////**end**///////"); ///this will be called after the callback attached by the interceptor
        log("MethodEntered() thisObject=" + thisObject + " method=" + method + " descriptor=" + className + " dex_pc=" + dexPc + "methodName=" + stringMethodName);
        //just test the method
        //if(!method.isNull()) log("-/testing this method : " +  Memory.readU32(method.add(8)));
        // NOW GETTING THE ARGUMENTS
        // there is one of the listener call graph when the method is called
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
    Interceptor.attach(callback, {
        onEnter: function (args) {
            this.thread = args[1];
            this.method = args[3];
            log("MethodEntered()  from the Interceptor ---method=" + this.method + " context=" + JSON.stringify(this.context));
            let current_sp = this.context.sp; 
            let current_pc = this.context.pc;
            let stack_offset_counter = 0;
            let dword_size = 4;
            let dex_pc_offset = 28; //(7*Process.PointerSize)
            let dex_pc_ptr_offset = 12; //(3*Process.pointerSize)
            let code_item_offset = 16;
            let classLinker_offset = 284;
            let thread: NativePointer = this.thread;
            let thread_pattern: any = thread.toMatchPattern();
            let matchList: MemoryScanMatch[] = Memory.scanSync(current_sp,2048, thread_pattern); 
            log("match list length " + matchList.length);
            var i:number = 0;
            do { 
                let thread_stack_pointer: NativePointer = matchList[i].address;
                try{
                    let prospective_shadowFrame: NativePointer = Memory.readPointer(thread_stack_pointer.add(2*dword_size));
                    let prospective_method: NativePointer  = Memory.readPointer(prospective_shadowFrame.add(1*Process.pointerSize));
                    if(prospective_method.equals(this.method)){
                        log(" //////////////**start**/////////////");
                        log("methodEntered: called from: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n\t"));
                        log("Method: " + prospective_method);
                        //log("called from: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n\t"));
                        log("Shadow frame :" + prospective_shadowFrame + " thread position " + i);
                        let prospective_shadow_frame_code_item = Memory.readPointer(thread_stack_pointer.add(dword_size)); 
                        log("Shadow frame code_item = " + prospective_shadow_frame_code_item);
                        let number_registers = Memory.readU16(prospective_shadow_frame_code_item);
                        let number_inputs = Memory.readU16(prospective_shadow_frame_code_item.add(2));
                        log("number of registers = " + number_registers + " number of inputs " + number_inputs);
                        if(number_inputs <= number_registers){
                            let arg_offset: number = number_registers - number_inputs;
                            let shadow_frame_number_vregs: number = Memory.readU32(prospective_shadowFrame.add(24)); 
                            log("number of vreg " + shadow_frame_number_vregs);
                            let shadow_frame_vregs_: NativePointer = (prospective_shadowFrame.add(36));
                            let args: NativePointer = shadow_frame_vregs_.add(arg_offset * Process.pointerSize);
                            let args_size: number = shadow_frame_number_vregs - arg_offset; 
                            log("args pointer = " + args + " size = " + args_size);
                            let result_register = Memory.readPointer(thread_stack_pointer.add(3*dword_size)); //because the biggest size of Jvalue is 4+4 bytes =2 * dword
                            log("Result register  = " + result_register);
                            let stay_in_interpreter = Memory.readInt(thread_stack_pointer.add(5*dword_size)); //because the biggest size of Jvalue is 4+4 bytes =2 * dword
                            log("stay in interpreter = " + stay_in_interpreter);
                            //TO GET THE SHORTY I NEED TO HAVE THE INTERFACE METHOD FIRST BY USING GetInterfaceMethodIfProxy()
                            //IN THE ART SOURCE CODE, THIS METHOD CALLS Runtime::Current()->GetClassLinker()->FindMethodForProxy(this); AND RETURN THE RESULT 
                            // AND BECAUSE THE LATEST IS EXPOSED, I WILL START BY IMPLEMENTING IT, I DONT USE THE CACHE AS IN THE GetInterfaceMethodIfProxy()

                            
                            let class_linker: NativePointer = Memory.readPointer(runtime.add(classLinker_offset));  
                            log("classLinker : " + class_linker);
                            let interfaceMethod = findMethodForProxy(class_linker, prospective_method);
                            log("Interface Method obtained" + interfaceMethod);

                            // NOW GETTING THE SHORTY FROM THE INTERFACE METHOD (method_index means index in the corresponding method_ids in the dex_file)(and the methood_id is the index in string_ids)
                            let declaringClass: NativePointer = Memory.readPointer(interfaceMethod);
                            log ("Declaring class = " + declaringClass);
                            let dexCache: NativePointer = Memory.readPointer(declaringClass.add(16));
                            log ("Dexcache = " + dexCache);
                            let dexfile: NativePointer = Memory.readPointer(dexCache.add(16));
                            log("dexFile" + dexfile);
                            let dex_method_index: number = Memory.readU16(interfaceMethod.add(8));
                            log("dex_method_index" + dex_method_index);
                            let method_ids: NativePointer =  Memory.readPointer(dexfile.add(48));
                            log("method_ids array" + method_ids);
                            let method_id: NativePointer = Memory.readPointer(method_ids.add(dex_method_index*8 + 2));
                            log("method_id " + method_id);
                            let proto_ids: NativePointer =  Memory.readPointer(dexfile.add(52));
                            log("proto_ids array: " + proto_ids);
                            let proto_index: number  =  method_id.add(method_id.shl(1)).toInt32();// - ----------------- to see deeply
                            log("proto index " + proto_index);
                            let proto_id: NativePointer =  Memory.readPointer(proto_ids.add(proto_index * 4));
                            log("proto_id in the array" + proto_id);
                            let string_ids: NativePointer = Memory.readPointer(dexfile.add(36));
                            log("string_ids array " + string_ids);
                            let dex_file_begin: NativePointer = Memory.readPointer(dexfile.add(4));
                            log("dex_file_begin " + dex_file_begin);
                            let prototype_string_offset: NativePointer = Memory.readPointer(string_ids.add(proto_id.shl(2)));
                            log("prototype_string offsett " + prototype_string_offset);
                            if(Memory.readPointer(dex_file_begin.add(prototype_string_offset)).equals(NULL)) log("error in getting the shorty"); 
                            let prototype_string_address: NativePointer = dex_file_begin.add(prototype_string_offset.add(1));
                            log("prototype_string_address : " + prototype_string_address);
                            
                            log(" first character = " + Memory.readUtf8String(prototype_string_address, 1)); 


                            
                            




                        }
                        break;
                    }else{
                        continue;
                    }
                } catch (error) {
                    //log("Error!");
                }
                //i++;
            } while(++i < matchList.length);
        },
        onLeave: function (retval) {
          //log("Leaving the on enter callback");
        }
      });

    return callback;
}


function makeMethodExited(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number, returnValue: NativePointer): void => {
        log("MethodExited() thisObject=" + thisObject + " method=" + method + " JValue=" + returnValue);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32","pointer"]);
    retainedHandles.push(callback);
    return callback;
}

function makeListenerMethod(name: string): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer): void => {
        log(name + " was called!");
    }, "void", ["pointer", "pointer"]);
    retainedHandles.push(callback);

    return callback;
}

function makeFieldRead(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number, field: NativePointer): void => {
        log("FieldRead() thisObject=" + thisObject + " method=" + method+ " fieldObject="+field);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32","pointer"]);
    retainedHandles.push(callback);

    return callback;
}

function makeFieldWritten(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number, field: NativePointer, field_value: NativePointer): void => {
        log("FieldWritten() thisObject=" + thisObject + " method=" + method);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32","pointer","pointer"]);
    retainedHandles.push(callback);

    return callback;
}

class StdString {
    handle: NativePointer;

    constructor() {    
        this.handle = Memory.alloc(3 * Process.pointerSize);
    }

    dispose(): void {
        if (!this.isTiny()) {
            //operatorDelete(this.getAllocatedBuffer());
        }
    }

    read(): string {
        //log(hexdump(this.handle, { length: 12 }));
        let str: string | null = null;
        if (this.isTiny()) {
            str = Memory.readUtf8String(this.handle.add(1));  ///////////////////////////  1*Process.pointerSize
        } else {
            str = Memory.readUtf8String(this.getAllocatedBuffer());
        }
        return (str !== null) ? str : "";
    }
    
    private isTiny(): boolean {
        return (Memory.readU8(this.handle) & 1) === 0;
    }

    private getAllocatedBuffer(): NativePointer {
        return Memory.readPointer(this.handle.add(2 * Process.pointerSize));
    }
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

    const innerDlopen: any = new NativeFunction(trampoline, "pointer", ["pointer", "int", "pointer"]);
    const addressInsideLibc = Module.findExportByName("libc.so", "read");
    
    //innerDlopen.trampoline = trampoline;

    return function (path: string): NativePointer {
        const handle = innerDlopen(Memory.allocUtf8String(path), 3, addressInsideLibc);
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

function printAsmExploreCallsGetShorty(impl: NativePointer, nlines: number): void{  
    let counter = 0;
    let cur: NativePointer = impl;
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
                    ebx = eax.add(ptr("0x13f17")); 
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
    printAsm(innerFunction, 1000);
    log("------> end printing the inner function " + innerFunction);

    let counter_ebx_function = 192;
    counter_ebx_function = counter_ebx_function + 4;
    while (counter_ebx_function <= 1220) {    
        //let dwordfromebx: NativePointer =  ebx.add(ptr(counter_ebx_function));
        log("--------------> printing dword ptr [ebx + 0x" + counter_ebx_function.toString(16)  + " ]: ");
        printAsm(Memory.readPointer(ebx.add(ptr(counter_ebx_function))), 1000);
        log("--------------> end printing  dword ptr [ebx + 0x" + counter_ebx_function.toString(16)  + " ]: ");
        counter_ebx_function = counter_ebx_function + 4;
    }

}

function printAsm(impl: NativePointer, nlines: number, force: boolean = false): void{  
    let counter = 0;
    let cur: NativePointer = impl;
    log("---------------------------> printing the simple asm");
    while (counter < nlines) {    
        const insn = Instruction.parse(cur);
        log(insn.address + "--> ......... " + insn.toString()); 
        //counter++;
        cur = insn.next;  
        counter++; 
        if(insn.mnemonic=="ret") break;
    }
    log("----------------------------> end printing simple asm")
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

class StdInstrumentationStackDeque {
    // from the class definition https://github.com/llvm-mirror/libcxx/blob/master/include/deque
    // line 959 you have three parameters 
    // to simplify we remove the private inerhitrance with deque_base
    handle: NativePointer;
    __start_ : number = 0;
    //__block_size is a const (line 945). Initialized (line 1037)
    // in the __deque_block_size struct value_type size is 20 and 
    // refferring to the line  276 it is < 256 , so we have 4096/20 =~ 204
    __block_size : number = 204; 
    constructor(handle_: NativePointer) {
        log(" we construct the stack object"); 
        let __start_Offset  = 4*Process.pointerSize; 
        this.handle = handle_;
        this.__start_ = Memory.readUInt(handle_.add(__start_Offset));
        
    }

    // actualize other attributes at every read

    size(): number {
        // it is in the third parameter, first element of the compressed pair  https://www.boost.org/doc/libs/1_47_0/boost/detail/compressed_pair.hpp  
        let sizeOffset = 5*Process.pointerSize;
        let result = Memory.readUInt(this.handle.add(sizeOffset));  
        log ("- size of the instrumentation queue : " + result);
        return result;
    }

    __map_begin(): NativePointer {
        // it is in  the first parameter __map_,   witch is a split_buffer 
        // https://github.com/google/libcxx/blob/master/include/__split_buffer line 47  
        let sizeOffset = 1*Process.pointerSize;
        let result = Memory.readPointer(this.handle.add(sizeOffset)); 
        log ("- begin of the  map in instrumentation queue : " + result); 
        return result;
    }

    __map_end(): NativePointer {
        // it is in  the first parameter __map_,   witch is a split_buffer 
        // https://github.com/google/libcxx/blob/master/include/__split_buffer line 48 
        let endOffset = 2*Process.pointerSize;
        let result = Memory.readPointer(this.handle.add(endOffset));  
        log ("- end of the map of the instrumentation queue : " + result);
        return result;
    }
    __map_empty(): boolean {
        // it is compute from   the first parameter  __map_, witch is a split_buffer 
        // https://github.com/google/libcxx/blob/master/include/__split_buffer line 85
        let result =  this.__map_end().compare(this.__map_begin()) == 0;
        log ("- map  of the instrumentation queue  is empty: " + result);
        return result;
    }
    
    refresh(){
        let __start_Offset  = 4*Process.pointerSize; 
        this.__start_ = Memory.readUInt(this.handle.add(__start_Offset));
        log ("- start offset in the map of the instrumentation queue : " + this.__start_);
    }
    front(): NativePointer {
        // here we don't dereference the result, it is still a pointer 
        // defined at line 1788 https://github.com/llvm-mirror/libcxx/blob/master/include/deque
        this.refresh();
        log("---  we get the front of the deque"); 
        let __p : number =  this.__start_;
        log(" value of p " + __p); 
        let  __mp : NativePointer = this.__map_begin().add(Math.floor(__p / this.__block_size) * Process.pointerSize) ;
        log (" processing the __mp : " + __mp + " with ratio p/size : " +  Math.floor(__p / this.__block_size)
                                 + " p%size = " + __p % this.__block_size);
        let result : NativePointer = Memory.readPointer(__mp).add((__p % this.__block_size) * Process.pointerSize);
        log("final result " + result );
        return result;
    } 

    back(): NativePointer {
        // here we don't dereference the result, it is still a pointer 
        // defined at line 1815 https://github.com/llvm-mirror/libcxx/blob/master/include/deque
        this.refresh();
        log("---  we get the front of the deque"); 
        let __p : number =  this.size() + this.__start_ - 1;
        log(" value of p " + __p); 
        let  __mp : NativePointer = this.__map_begin().add(Math.floor(__p / this.__block_size) * Process.pointerSize) ;
        log (" processing the __mp : " + __mp + " with ratio p/size : " +  Math.floor(__p / this.__block_size)
                                 + " p%size = " + __p % this.__block_size);
        let result : NativePointer = Memory.readPointer(__mp).add((__p % this.__block_size) * Process.pointerSize);
        log("final result " + result );
        return result;
    } 
}

/*
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
    let cur: NativePointer = impl;
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
}*/
