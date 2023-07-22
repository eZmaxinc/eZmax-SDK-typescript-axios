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
 * A complex type that specifies configuration options related to changing a password.
 * @export
 * @interface ScimServiceProviderConfigChangePassword
 */
export interface ScimServiceProviderConfigChangePassword {
    /**
     * A Boolean value specifying whether or not the operation is supported.
     * @type {boolean}
     * @memberof ScimServiceProviderConfigChangePassword
     */
    'supported': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ScimServiceProviderConfigChangePassword Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectScimServiceProviderConfigChangePassword
 */
export class DataObjectScimServiceProviderConfigChangePassword {
   supported:boolean = false
}

/**
 * @export 
 * A ScimServiceProviderConfigChangePassword Validation Object
 * @class ValidationObjectScimServiceProviderConfigChangePassword
 */
export class ValidationObjectScimServiceProviderConfigChangePassword {
   supported = {
      type: 'boolean',
      required: true
   }
} 


