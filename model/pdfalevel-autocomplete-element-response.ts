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
 * A Pdfalevel AutocompleteElement Response
 * @export
 * @interface PdfalevelAutocompleteElementResponse
 */
export interface PdfalevelAutocompleteElementResponse {
    /**
     * The unique ID of the Pdfalevel
     * @type {number}
     * @memberof PdfalevelAutocompleteElementResponse
     */
    /*'pkiPdfalevelID': number;*/
    'pkiPdfalevelID': number;
    /**
     * The name of the Pdfalevel
     * @type {string}
     * @memberof PdfalevelAutocompleteElementResponse
     */
    /*'sPdfalevelName': string;*/
    'sPdfalevelName': string;
    /**
     * Whether the Pdfalevel is active or not
     * @type {boolean}
     * @memberof PdfalevelAutocompleteElementResponse
     */
    /*'bPdfalevelIsactive': boolean;*/
    'bPdfalevelIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PdfalevelAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPdfalevelAutocompleteElementResponse
 */
export class DataObjectPdfalevelAutocompleteElementResponse {
   pkiPdfalevelID:number = 0
   sPdfalevelName:string = ''
   bPdfalevelIsactive:boolean = false
}

/**
 * @export 
 * A PdfalevelAutocompleteElementResponse Validation Object
 * @class ValidationObjectPdfalevelAutocompleteElementResponse
 */
export class ValidationObjectPdfalevelAutocompleteElementResponse {
   pkiPdfalevelID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   sPdfalevelName = {
      type: 'string',
      pattern: /^.{0,15}$/,
      required: true
   }
   bPdfalevelIsactive = {
      type: 'boolean',
      required: true
   }
} 


