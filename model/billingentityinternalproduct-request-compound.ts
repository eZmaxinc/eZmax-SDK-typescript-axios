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


// May contain unused imports in some cases
// @ts-ignore
import { BillingentityinternalproductRequest } from './billingentityinternalproduct-request';

/**
 * @type BillingentityinternalproductRequestCompound
 * A Billingentityinternalproduct Object and children
 * @export
 */
export type BillingentityinternalproductRequestCompound = BillingentityinternalproductRequest;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A BillingentityinternalproductRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityinternalproductRequestCompound
 */
export class DataObjectBillingentityinternalproductRequestCompound {
    pkiBillingentityinternalproductID?:number = undefined
    fkiEzmaxproductID:number = 0
    fkiBillingentityexternalID:number = 0
}

/**
 * @export 
 * A BillingentityinternalproductRequestCompound Validation Object
 * @class ValidationObjectBillingentityinternalproductRequestCompound
 */
export class ValidationObjectBillingentityinternalproductRequestCompound {
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


