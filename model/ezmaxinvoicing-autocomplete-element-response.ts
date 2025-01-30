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
    /*'yyyymmEzmaxinvoicing': string;*/
    'yyyymmEzmaxinvoicing': string;
    /**
     * The unique ID of the Ezmaxinvoicing
     * @type {number}
     * @memberof EzmaxinvoicingAutocompleteElementResponse
     */
    /*'pkiEzmaxinvoicingID': number;*/
    'pkiEzmaxinvoicingID': number;
    /**
     * Whether the Ezmaxinvoicing is active or not
     * @type {boolean}
     * @memberof EzmaxinvoicingAutocompleteElementResponse
     */
    /*'bEzmaxinvoicingIsactive': boolean;*/
    'bEzmaxinvoicingIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzmaxinvoicingAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingAutocompleteElementResponse
 */
export class DataObjectEzmaxinvoicingAutocompleteElementResponse {
   yyyymmEzmaxinvoicing:string = ''
   pkiEzmaxinvoicingID:number = 0
   bEzmaxinvoicingIsactive:boolean = false
}

/**
 * @export 
 * A EzmaxinvoicingAutocompleteElementResponse Validation Object
 * @class ValidationObjectEzmaxinvoicingAutocompleteElementResponse
 */
export class ValidationObjectEzmaxinvoicingAutocompleteElementResponse {
   yyyymmEzmaxinvoicing = {
      type: 'string',
      maxLength: 7,
      required: true
   }
   pkiEzmaxinvoicingID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bEzmaxinvoicingIsactive = {
      type: 'boolean',
      required: true
   }
} 


