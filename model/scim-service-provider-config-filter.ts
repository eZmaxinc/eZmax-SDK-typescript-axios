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
 * A complex type that specifies FILTER options.
 * @export
 * @interface ScimServiceProviderConfigFilter
 */
export interface ScimServiceProviderConfigFilter {
    /**
     * A Boolean value specifying whether or not the operation is supported.
     * @type {boolean}
     * @memberof ScimServiceProviderConfigFilter
     */
    /*'supported': boolean;*/
    'supported': boolean;
    /**
     * An integer value specifying the maximum number of resources returned in a response.
     * @type {number}
     * @memberof ScimServiceProviderConfigFilter
     */
    /*'maxResults': number;*/
    'maxResults': number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ScimServiceProviderConfigFilter Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectScimServiceProviderConfigFilter
 */
export class DataObjectScimServiceProviderConfigFilter {
   supported:boolean = false
   maxResults:number = 0
}

/**
 * @export 
 * A ScimServiceProviderConfigFilter Validation Object
 * @class ValidationObjectScimServiceProviderConfigFilter
 */
export class ValidationObjectScimServiceProviderConfigFilter {
   supported = {
      type: 'boolean',
      required: true
   }
   maxResults = {
      type: 'integer',
      required: true
   }
} 


