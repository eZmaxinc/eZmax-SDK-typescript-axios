/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Emailtype AutocompleteElement Response
 * @export
 * @interface EmailtypeAutocompleteElementResponse
 */
export interface EmailtypeAutocompleteElementResponse {
    /**
     * The unique ID of the Emailtype.  Valid values:  |Value|Description| |-|-| |1|Office| |2|Home|
     * @type {number}
     * @memberof EmailtypeAutocompleteElementResponse
     */
    /*'pkiEmailtypeID': number;*/
    'pkiEmailtypeID': number;
    /**
     * The name of the Emailtype in the language of the requester
     * @type {string}
     * @memberof EmailtypeAutocompleteElementResponse
     */
    /*'sEmailtypeNameX': string;*/
    'sEmailtypeNameX': string;
    /**
     * Whether the Emailtype is active or not
     * @type {boolean}
     * @memberof EmailtypeAutocompleteElementResponse
     */
    /*'bEmailtypeIsactive': boolean;*/
    'bEmailtypeIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EmailtypeAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEmailtypeAutocompleteElementResponse
 */
export class DataObjectEmailtypeAutocompleteElementResponse {
   pkiEmailtypeID:number = 0
   sEmailtypeNameX:string = ''
   bEmailtypeIsactive:boolean = false
}

/**
 * @export 
 * A EmailtypeAutocompleteElementResponse Validation Object
 * @class ValidationObjectEmailtypeAutocompleteElementResponse
 */
export class ValidationObjectEmailtypeAutocompleteElementResponse {
   pkiEmailtypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEmailtypeNameX = {
      type: 'string',
      pattern: /^.{0,15}$/,
      required: true
   }
   bEmailtypeIsactive = {
      type: 'boolean',
      required: true
   }
} 


