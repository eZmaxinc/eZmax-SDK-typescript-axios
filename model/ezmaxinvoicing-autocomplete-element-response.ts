/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * A Ezmaxinvoicing AutocompleteElement Response
 * @export
 * @interface EzmaxinvoicingAutocompleteElementResponse
 */
export interface EzmaxinvoicingAutocompleteElementResponse {
    /**
     * The YYYYMM period of the Ezmaxinvoicing
     * @type {string}
     * @memberof EzmaxinvoicingAutocompleteElementResponse
     */
    'yyyymmEzmaxinvoicing': string;
    /**
     * The unique ID of the Ezmaxinvoicing
     * @type {number}
     * @memberof EzmaxinvoicingAutocompleteElementResponse
     */
    'pkiEzmaxinvoicingID': number;
    /**
     * Whether the Ezmaxinvoicing is active or not
     * @type {boolean}
     * @memberof EzmaxinvoicingAutocompleteElementResponse
     */
    'bEzmaxinvoicingIsactive': boolean;
}
/**
 * A EzmaxinvoicingAutocompleteElementResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzmaxinvoicingAutocompleteElementResponse
 */
export class DefaultObjectEzmaxinvoicingAutocompleteElementResponse extends DefaultObject {
   yyyymmEzmaxinvoicing:string = ''
   pkiEzmaxinvoicingID:number = 0
   bEzmaxinvoicingIsactive:boolean = false
}


