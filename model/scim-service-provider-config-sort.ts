/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A complex type that specifies Sort configuration options.
 * @export
 * @interface ScimServiceProviderConfigSort
 */
export interface ScimServiceProviderConfigSort {
    /**
     * A Boolean value specifying whether or not sorting is supported.
     * @type {boolean}
     * @memberof ScimServiceProviderConfigSort
     */
    /*'supported': boolean;*/
    'supported': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ScimServiceProviderConfigSort Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectScimServiceProviderConfigSort
 */
export class DataObjectScimServiceProviderConfigSort {
   supported:boolean = false
}

/**
 * @export 
 * A ScimServiceProviderConfigSort Validation Object
 * @class ValidationObjectScimServiceProviderConfigSort
 */
export class ValidationObjectScimServiceProviderConfigSort {
   supported = {
      type: 'boolean',
      required: true
   }
} 


