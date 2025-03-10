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
 * A Billingentityexternal AutocompleteElement Response
 * @export
 * @interface BillingentityexternalAutocompleteElementResponse
 */
export interface BillingentityexternalAutocompleteElementResponse {
    /**
     * The unique ID of the Billingentityexternal
     * @type {number}
     * @memberof BillingentityexternalAutocompleteElementResponse
     */
    /*'pkiBillingentityexternalID': number;*/
    'pkiBillingentityexternalID': number;
    /**
     * The description of the Billingentityexternal
     * @type {string}
     * @memberof BillingentityexternalAutocompleteElementResponse
     */
    /*'sBillingentityexternalDescription': string;*/
    'sBillingentityexternalDescription': string;
    /**
     * Whether the Billingentityexternal is active or not
     * @type {boolean}
     * @memberof BillingentityexternalAutocompleteElementResponse
     */
    /*'bBillingentityexternalIsactive': boolean;*/
    'bBillingentityexternalIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A BillingentityexternalAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityexternalAutocompleteElementResponse
 */
export class DataObjectBillingentityexternalAutocompleteElementResponse {
   pkiBillingentityexternalID:number = 0
   sBillingentityexternalDescription:string = ''
   bBillingentityexternalIsactive:boolean = false
}

/**
 * @export 
 * A BillingentityexternalAutocompleteElementResponse Validation Object
 * @class ValidationObjectBillingentityexternalAutocompleteElementResponse
 */
export class ValidationObjectBillingentityexternalAutocompleteElementResponse {
   pkiBillingentityexternalID = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   sBillingentityexternalDescription = {
      type: 'string',
      required: true
   }
   bBillingentityexternalIsactive = {
      type: 'boolean',
      required: true
   }
} 


