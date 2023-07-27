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
 * A Phonetype AutocompleteElement Response
 * @export
 * @interface PhonetypeAutocompleteElementResponse
 */
export interface PhonetypeAutocompleteElementResponse {
    /**
     * The unique ID of the Phonetype.  Valid values:  |Value|Description| |-|-| |1|Office| |2|Home| |3|Mobile| |4|Fax| |5|Pager| |6|Toll Free|
     * @type {number}
     * @memberof PhonetypeAutocompleteElementResponse
     */
    'pkiPhonetypeID': number;
    /**
     * The name of the Phonetype in the language of the requester
     * @type {string}
     * @memberof PhonetypeAutocompleteElementResponse
     */
    'sPhonetypeNameX': string;
    /**
     * Whether the Phonetype is active or not
     * @type {boolean}
     * @memberof PhonetypeAutocompleteElementResponse
     */
    'bPhonetypeIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PhonetypeAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPhonetypeAutocompleteElementResponse
 */
export class DataObjectPhonetypeAutocompleteElementResponse {
   pkiPhonetypeID:number = 0
   sPhonetypeNameX:string = ''
   bPhonetypeIsactive:boolean = false
}

/**
 * @export 
 * A PhonetypeAutocompleteElementResponse Validation Object
 * @class ValidationObjectPhonetypeAutocompleteElementResponse
 */
export class ValidationObjectPhonetypeAutocompleteElementResponse {
   pkiPhonetypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sPhonetypeNameX = {
      type: 'string',
      pattern: '/^.{0,20}$/',
      required: true
   }
   bPhonetypeIsactive = {
      type: 'boolean',
      required: true
   }
} 


