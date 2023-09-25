/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Ezmaxproduct AutocompleteElement Response
 * @export
 * @interface EzmaxproductAutocompleteElementResponse
 */
export interface EzmaxproductAutocompleteElementResponse {
    /**
     * The unique ID of the Ezmaxproduct
     * @type {number}
     * @memberof EzmaxproductAutocompleteElementResponse
     */
    'pkiEzmaxproductID': number;
    /**
     * The description of the Ezmaxproduct in the language of the requester
     * @type {string}
     * @memberof EzmaxproductAutocompleteElementResponse
     */
    'sEzmaxproductDescriptionX': string;
    /**
     * Whether the Ezmaxproduct is active or not
     * @type {boolean}
     * @memberof EzmaxproductAutocompleteElementResponse
     */
    'bEzmaxproductIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzmaxproductAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxproductAutocompleteElementResponse
 */
export class DataObjectEzmaxproductAutocompleteElementResponse {
   pkiEzmaxproductID:number = 0
   sEzmaxproductDescriptionX:string = ''
   bEzmaxproductIsactive:boolean = false
}

/**
 * @export 
 * A EzmaxproductAutocompleteElementResponse Validation Object
 * @class ValidationObjectEzmaxproductAutocompleteElementResponse
 */
export class ValidationObjectEzmaxproductAutocompleteElementResponse {
   pkiEzmaxproductID = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   sEzmaxproductDescriptionX = {
      type: 'string',
      required: true
   }
   bEzmaxproductIsactive = {
      type: 'boolean',
      required: true
   }
} 


