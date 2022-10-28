/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * This is a debug object containing debugging information on the actual function
 * @export
 * @interface CommonResponseObjDebugPayload
 */
export interface CommonResponseObjDebugPayload {
    /**
     * The minimum version of the function that can be called
     * @type {number}
     * @memberof CommonResponseObjDebugPayload
     */
    'iVersionMin': number;
    /**
     * The maximum version of the function that can be called
     * @type {number}
     * @memberof CommonResponseObjDebugPayload
     */
    'iVersionMax': number;
    /**
     * An array of permissions required to access this function.  If the value \"0\" is present in the array, anyone can call this function.  You must have one of the permission to access the function. You don\'t need to have all of them.
     * @type {Array<number>}
     * @memberof CommonResponseObjDebugPayload
     */
    'a_RequiredPermission': Array<number>;
}
/**
 * A CommonResponseObjDebugPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCommonResponseObjDebugPayload
 */
export class DefaultObjectCommonResponseObjDebugPayload extends DefaultObject {
   iVersionMin:number = 0
   iVersionMax:number = 0
   a_RequiredPermission:Array<number> = []
}


