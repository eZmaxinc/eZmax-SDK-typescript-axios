/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * 
 * @export
 * @interface ScimGroupMember
 */
export interface ScimGroupMember {
    /**
     * 
     * @type {string}
     * @memberof ScimGroupMember
     */
    'value'?: string;
    /**
     * 
     * @type {string}
     * @memberof ScimGroupMember
     */
    'display'?: string;
    /**
     * 
     * @type {string}
     * @memberof ScimGroupMember
     */
    'type'?: string;
    /**
     * 
     * @type {string}
     * @memberof ScimGroupMember
     */
    '$ref'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ScimGroupMember Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectScimGroupMember
 */
export class DataObjectScimGroupMember {
   value?:string = undefined
   display?:string = undefined
   type?:string = undefined
   $ref?:string = undefined
}

/**
 * @export 
 * A ScimGroupMember Validation Object
 * @class ValidationObjectScimGroupMember
 */
export class ValidationObjectScimGroupMember {
   value = {
      type: 'string',
      required: false
   }
   display = {
      type: 'string',
      required: false
   }
   type = {
      type: 'string',
      required: false
   }
   $ref = {
      type: 'string',
      required: false
   }
} 


