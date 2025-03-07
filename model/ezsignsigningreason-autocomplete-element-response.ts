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
 * A Ezsignsigningreason AutocompleteElement Response
 * @export
 * @interface EzsignsigningreasonAutocompleteElementResponse
 */
export interface EzsignsigningreasonAutocompleteElementResponse {
    /**
     * The unique ID of the Ezsignsigningreason
     * @type {number}
     * @memberof EzsignsigningreasonAutocompleteElementResponse
     */
    /*'pkiEzsignsigningreasonID': number;*/
    'pkiEzsignsigningreasonID': number;
    /**
     * The description of the Ezsignsigningreason in the language of the requester
     * @type {string}
     * @memberof EzsignsigningreasonAutocompleteElementResponse
     */
    /*'sEzsignsigningreasonDescriptionX': string;*/
    'sEzsignsigningreasonDescriptionX': string;
    /**
     * Whether the ezsignsigningreason is active or not
     * @type {boolean}
     * @memberof EzsignsigningreasonAutocompleteElementResponse
     */
    /*'bEzsignsigningreasonIsactive': boolean;*/
    'bEzsignsigningreasonIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsigningreasonAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsigningreasonAutocompleteElementResponse
 */
export class DataObjectEzsignsigningreasonAutocompleteElementResponse {
   pkiEzsignsigningreasonID:number = 0
   sEzsignsigningreasonDescriptionX:string = ''
   bEzsignsigningreasonIsactive:boolean = false
}

/**
 * @export 
 * A EzsignsigningreasonAutocompleteElementResponse Validation Object
 * @class ValidationObjectEzsignsigningreasonAutocompleteElementResponse
 */
export class ValidationObjectEzsignsigningreasonAutocompleteElementResponse {
   pkiEzsignsigningreasonID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   sEzsignsigningreasonDescriptionX = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: true
   }
   bEzsignsigningreasonIsactive = {
      type: 'boolean',
      required: true
   }
} 


