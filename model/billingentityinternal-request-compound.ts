/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { BillingentityinternalRequest } from './billingentityinternal-request';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualBillingentityinternalDescription } from './multilingual-billingentityinternal-description';

/**
 * @type BillingentityinternalRequestCompound
 * A Billingentityinternal Object and children
 * @export
 */
export type BillingentityinternalRequestCompound = BillingentityinternalRequest;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualBillingentityinternalDescription } from './'
// @ts-ignore
import { ValidationObjectMultilingualBillingentityinternalDescription } from './'

/**
 * @export 
 * A BillingentityinternalRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityinternalRequestCompound
 */
export class DataObjectBillingentityinternalRequestCompound {
   pkiBillingentityinternalID?:number = undefined
   objBillingentityinternalDescription:MultilingualBillingentityinternalDescription = new DataObjectMultilingualBillingentityinternalDescription()
}

/**
 * @export 
 * A BillingentityinternalRequestCompound Validation Object
 * @class ValidationObjectBillingentityinternalRequestCompound
 */
export class ValidationObjectBillingentityinternalRequestCompound {
   pkiBillingentityinternalID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   objBillingentityinternalDescription = new ValidationObjectMultilingualBillingentityinternalDescription()
} 


