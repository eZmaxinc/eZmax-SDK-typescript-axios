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
 * The description of the Ezsignsigningreason
 * @export
 * @interface MultilingualEzsignsigningreasonDescription
 */
export interface MultilingualEzsignsigningreasonDescription {
    /**
     * The description of the Ezsignsigningreason in French
     * @type {string}
     * @memberof MultilingualEzsignsigningreasonDescription
     */
    /*'sEzsignsigningreasonDescription1'?: string;*/
    'sEzsignsigningreasonDescription1'?: string;
    /**
     * The description of the Ezsignsigningreason in English
     * @type {string}
     * @memberof MultilingualEzsignsigningreasonDescription
     */
    /*'sEzsignsigningreasonDescription2'?: string;*/
    'sEzsignsigningreasonDescription2'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A MultilingualEzsignsigningreasonDescription Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectMultilingualEzsignsigningreasonDescription
 */
export class DataObjectMultilingualEzsignsigningreasonDescription {
   sEzsignsigningreasonDescription1?:string = undefined
   sEzsignsigningreasonDescription2?:string = undefined
}

/**
 * @export 
 * A MultilingualEzsignsigningreasonDescription Validation Object
 * @class ValidationObjectMultilingualEzsignsigningreasonDescription
 */
export class ValidationObjectMultilingualEzsignsigningreasonDescription {
   sEzsignsigningreasonDescription1 = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: false
   }
   sEzsignsigningreasonDescription2 = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: false
   }
} 


