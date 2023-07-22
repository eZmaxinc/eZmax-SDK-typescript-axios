/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Billingentityinternalproduct Object
 * @export
 * @interface BillingentityinternalproductRequest
 */
export interface BillingentityinternalproductRequest {
    /**
     * The unique ID of the Billingentityinternalproduct
     * @type {number}
     * @memberof BillingentityinternalproductRequest
     */
    'pkiBillingentityinternalproductID'?: number;
    /**
     * The unique ID of the Ezmaxproduct
     * @type {number}
     * @memberof BillingentityinternalproductRequest
     */
    'fkiEzmaxproductID': number;
    /**
     * The unique ID of the Billingentityexternal
     * @type {number}
     * @memberof BillingentityinternalproductRequest
     */
    'fkiBillingentityexternalID': number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A BillingentityinternalproductRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityinternalproductRequest
 */
export class DataObjectBillingentityinternalproductRequest {
   pkiBillingentityinternalproductID?:number = undefined
   fkiEzmaxproductID:number = 0
   fkiBillingentityexternalID:number = 0
}

/**
 * @export 
 * A BillingentityinternalproductRequest Validation Object
 * @class ValidationObjectBillingentityinternalproductRequest
 */
export class ValidationObjectBillingentityinternalproductRequest {
   pkiBillingentityinternalproductID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   fkiEzmaxproductID = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   fkiBillingentityexternalID = {
      type: 'integer',
      minimum: 1,
      required: true
   }
} 


