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
 * Branding AutocompleteElement Response
 * @export
 * @interface BrandingAutocompleteElementResponse
 */
export interface BrandingAutocompleteElementResponse {
    /**
     * The Description of the Branding in the language of the requester
     * @type {string}
     * @memberof BrandingAutocompleteElementResponse
     */
    /*'sBrandingDescriptionX': string;*/
    'sBrandingDescriptionX': string;
    /**
     * The unique ID of the Branding
     * @type {number}
     * @memberof BrandingAutocompleteElementResponse
     */
    /*'pkiBrandingID': number;*/
    'pkiBrandingID': number;
    /**
     * Whether the Branding is active or not
     * @type {boolean}
     * @memberof BrandingAutocompleteElementResponse
     */
    /*'bBrandingIsactive': boolean;*/
    'bBrandingIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A BrandingAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBrandingAutocompleteElementResponse
 */
export class DataObjectBrandingAutocompleteElementResponse {
   sBrandingDescriptionX:string = ''
   pkiBrandingID:number = 0
   bBrandingIsactive:boolean = false
}

/**
 * @export 
 * A BrandingAutocompleteElementResponse Validation Object
 * @class ValidationObjectBrandingAutocompleteElementResponse
 */
export class ValidationObjectBrandingAutocompleteElementResponse {
   sBrandingDescriptionX = {
      type: 'string',
      required: true
   }
   pkiBrandingID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bBrandingIsactive = {
      type: 'boolean',
      required: true
   }
} 


