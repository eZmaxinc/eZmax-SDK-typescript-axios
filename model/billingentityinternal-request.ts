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


// May contain unused imports in some cases
// @ts-ignore
import type { MultilingualBillingentityinternalDescription } from './multilingual-billingentityinternal-description';

/**
 * A Billingentityinternal Object
 * @export
 * @interface BillingentityinternalRequest
 */
export interface BillingentityinternalRequest {
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof BillingentityinternalRequest
     */
    /*'pkiBillingentityinternalID'?: number;*/
    'pkiBillingentityinternalID'?: number;
    /**
     * 
     * @type {MultilingualBillingentityinternalDescription}
     * @memberof BillingentityinternalRequest
     */
    /*'objBillingentityinternalDescription': MultilingualBillingentityinternalDescription;*/
    'objBillingentityinternalDescription': MultilingualBillingentityinternalDescription;
}
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
 * A BillingentityinternalRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityinternalRequest
 */
export class DataObjectBillingentityinternalRequest {
   pkiBillingentityinternalID?:number = undefined
   objBillingentityinternalDescription:MultilingualBillingentityinternalDescription = new DataObjectMultilingualBillingentityinternalDescription()
}

/**
 * @export 
 * A BillingentityinternalRequest Validation Object
 * @class ValidationObjectBillingentityinternalRequest
 */
export class ValidationObjectBillingentityinternalRequest {
   pkiBillingentityinternalID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   objBillingentityinternalDescription = new ValidationObjectMultilingualBillingentityinternalDescription()
} 


