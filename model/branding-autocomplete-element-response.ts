/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

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
    'sBrandingDescriptionX': string;
    /**
     * The unique ID of the Branding
     * @type {number}
     * @memberof BrandingAutocompleteElementResponse
     */
    'pkiBrandingID': number;
    /**
     * Whether the Branding is active or not
     * @type {boolean}
     * @memberof BrandingAutocompleteElementResponse
     */
    'bBrandingIsactive': boolean;
}
/**
 * A BrandingAutocompleteElementResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectBrandingAutocompleteElementResponse
 */
export class DefaultObjectBrandingAutocompleteElementResponse extends DefaultObject {
   sBrandingDescriptionX:string = ''
   pkiBrandingID:number = 0
   bBrandingIsactive:boolean = false
}


