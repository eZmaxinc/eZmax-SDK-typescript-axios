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
 * A Font AutocompleteElement Response
 * @export
 * @interface FontAutocompleteElementResponse
 */
export interface FontAutocompleteElementResponse {
    /**
     * The name of the Font
     * @type {string}
     * @memberof FontAutocompleteElementResponse
     */
    /*'sFontName': string;*/
    'sFontName': string;
    /**
     * The unique ID of the Font
     * @type {number}
     * @memberof FontAutocompleteElementResponse
     */
    /*'pkiFontID': number;*/
    'pkiFontID': number;
    /**
     * Whether the Font is active or not
     * @type {boolean}
     * @memberof FontAutocompleteElementResponse
     */
    /*'bFontIsactive': boolean;*/
    'bFontIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A FontAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectFontAutocompleteElementResponse
 */
export class DataObjectFontAutocompleteElementResponse {
   sFontName:string = ''
   pkiFontID:number = 0
   bFontIsactive:boolean = false
}

/**
 * @export 
 * A FontAutocompleteElementResponse Validation Object
 * @class ValidationObjectFontAutocompleteElementResponse
 */
export class ValidationObjectFontAutocompleteElementResponse {
   sFontName = {
      type: 'string',
      pattern: '/^.{0,50}$/',
      required: true
   }
   pkiFontID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bFontIsactive = {
      type: 'boolean',
      required: true
   }
} 


