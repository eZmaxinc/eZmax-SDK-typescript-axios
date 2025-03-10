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
 * A Ezdoctemplatetype AutocompleteElement Response
 * @export
 * @interface EzdoctemplatetypeAutocompleteElementResponse
 */
export interface EzdoctemplatetypeAutocompleteElementResponse {
    /**
     * The unique ID of the Ezdoctemplatetype
     * @type {number}
     * @memberof EzdoctemplatetypeAutocompleteElementResponse
     */
    /*'pkiEzdoctemplatetypeID': number;*/
    'pkiEzdoctemplatetypeID': number;
    /**
     * The description of the Ezdoctemplatetype in the language of the requester
     * @type {string}
     * @memberof EzdoctemplatetypeAutocompleteElementResponse
     */
    /*'sEzdoctemplatetypeDescriptionX': string;*/
    'sEzdoctemplatetypeDescriptionX': string;
    /**
     * Whether the Ezdoctemplatetype is active or not
     * @type {boolean}
     * @memberof EzdoctemplatetypeAutocompleteElementResponse
     */
    /*'bEzdoctemplatetypeIsactive': boolean;*/
    'bEzdoctemplatetypeIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzdoctemplatetypeAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzdoctemplatetypeAutocompleteElementResponse
 */
export class DataObjectEzdoctemplatetypeAutocompleteElementResponse {
   pkiEzdoctemplatetypeID:number = 0
   sEzdoctemplatetypeDescriptionX:string = ''
   bEzdoctemplatetypeIsactive:boolean = false
}

/**
 * @export 
 * A EzdoctemplatetypeAutocompleteElementResponse Validation Object
 * @class ValidationObjectEzdoctemplatetypeAutocompleteElementResponse
 */
export class ValidationObjectEzdoctemplatetypeAutocompleteElementResponse {
   pkiEzdoctemplatetypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   sEzdoctemplatetypeDescriptionX = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: true
   }
   bEzdoctemplatetypeIsactive = {
      type: 'boolean',
      required: true
   }
} 


