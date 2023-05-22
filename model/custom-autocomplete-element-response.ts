/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Generic AutocompleteElement Response
 * @export
 * @interface CustomAutocompleteElementResponse
 */
export interface CustomAutocompleteElementResponse {
    /**
     * The Category for the dropdown or an empty string if not categorized
     * @type {string}
     * @memberof CustomAutocompleteElementResponse
     */
    'sCategory': string;
    /**
     * The Description of the element
     * @type {string}
     * @memberof CustomAutocompleteElementResponse
     */
    'sLabel': string;
    /**
     * The Unique ID of the element
     * @type {string}
     * @memberof CustomAutocompleteElementResponse
     */
    'sValue': string;
    /**
     * The Unique ID of the element
     * @type {string}
     * @memberof CustomAutocompleteElementResponse
     * @deprecated
     */
    'mValue'?: string;
    /**
     * Indicates if the element is active
     * @type {boolean}
     * @memberof CustomAutocompleteElementResponse
     */
    'bActive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomAutocompleteElementResponse
 */
export class DataObjectCustomAutocompleteElementResponse {
   sCategory:string = ''
   sLabel:string = ''
   sValue:string = ''
   mValue?:string = undefined
   bActive:boolean = false
}

/**
 * @export 
 * A CustomAutocompleteElementResponse Validation Object
 * @class ValidationObjectCustomAutocompleteElementResponse
 */
export class ValidationObjectCustomAutocompleteElementResponse {
   sCategory = {
      type: 'string',
      required: true
   }
   sLabel = {
      type: 'string',
      required: true
   }
   sValue = {
      type: 'string',
      required: true
   }
   mValue = {
      type: 'string',
      required: false
   }
   bActive = {
      type: 'boolean',
      required: true
   }
} 


