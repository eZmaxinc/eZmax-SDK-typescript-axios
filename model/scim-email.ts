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
 * @interface ScimEmail
 */
export interface ScimEmail {
    /**
     * The email address.
     * @type {string}
     * @memberof ScimEmail
     */
    'value'?: string;
    /**
     * 
     * @type {boolean}
     * @memberof ScimEmail
     */
    'primary'?: boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ScimEmail Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectScimEmail
 */
export class DataObjectScimEmail {
   value?:string = undefined
   primary?:boolean = undefined
}

/**
 * @export 
 * A ScimEmail Validation Object
 * @class ValidationObjectScimEmail
 */
export class ValidationObjectScimEmail {
   value = {
      type: 'string',
      required: false
   }
   primary = {
      type: 'boolean',
      required: false
   }
} 

