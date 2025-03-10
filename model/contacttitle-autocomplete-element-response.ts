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
 * A Contacttitle AutocompleteElement Response
 * @export
 * @interface ContacttitleAutocompleteElementResponse
 */
export interface ContacttitleAutocompleteElementResponse {
    /**
     * The unique ID of the Contacttitle.  Valid values:  |Value|Description| |-|-| |1|Ms.| |2|Mr.| |4|(Blank)| |5|Me (For Notaries)|
     * @type {number}
     * @memberof ContacttitleAutocompleteElementResponse
     */
    /*'pkiContacttitleID': number;*/
    'pkiContacttitleID': number;
    /**
     * The name of the Contacttitle in the language of the requester
     * @type {string}
     * @memberof ContacttitleAutocompleteElementResponse
     */
    /*'sContacttitleNameX': string;*/
    'sContacttitleNameX': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ContacttitleAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectContacttitleAutocompleteElementResponse
 */
export class DataObjectContacttitleAutocompleteElementResponse {
   pkiContacttitleID:number = 0
   sContacttitleNameX:string = ''
}

/**
 * @export 
 * A ContacttitleAutocompleteElementResponse Validation Object
 * @class ValidationObjectContacttitleAutocompleteElementResponse
 */
export class ValidationObjectContacttitleAutocompleteElementResponse {
   pkiContacttitleID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sContacttitleNameX = {
      type: 'string',
      pattern: /^.{0,10}$/,
      required: true
   }
} 


