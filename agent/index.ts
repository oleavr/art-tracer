import { trace } from "./tracer";
import { log } from "./logger";

setTimeout(() => {
    try {
        trace({
            onEnter(methodName) {
                console.log("onEnter", methodName);
            },
            onLeave(methodName) {
            }
        });    
        //},/.*/,/java.lang/); 
    } catch (error) {
        log("Oups --------> " + error.stack);
    }    
}, 2000);
