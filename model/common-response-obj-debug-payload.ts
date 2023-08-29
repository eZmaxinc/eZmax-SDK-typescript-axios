/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



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
    /**
     * Wheter the current route is deprecated or not
     * @type {boolean}
     * @memberof CommonResponseObjDebugPayload
     */
    'bVersionDeprecated': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CommonResponseObjDebugPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonResponseObjDebugPayload
 */
export class DataObjectCommonResponseObjDebugPayload {
   iVersionMin:number = 0
   iVersionMax:number = 0
   a_RequiredPermission:Array<number> = []
   bVersionDeprecated:boolean = false
}

/**
 * @export 
 * A CommonResponseObjDebugPayload Validation Object
 * @class ValidationObjectCommonResponseObjDebugPayload
 */
export class ValidationObjectCommonResponseObjDebugPayload {
   iVersionMin = {
      type: 'integer',
      required: true
   }
   iVersionMax = {
      type: 'integer',
      required: true
   }
   a_RequiredPermission = {
      type: 'array',
      required: true
   }
   bVersionDeprecated = {
      type: 'boolean',
      required: true
   }
} 


