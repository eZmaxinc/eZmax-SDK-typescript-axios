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


// May contain unused imports in some cases
// @ts-ignore
import { BillingentityinternalResponse } from './billingentityinternal-response';
// May contain unused imports in some cases
// @ts-ignore
import { BillingentityinternalproductResponseCompound } from './billingentityinternalproduct-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualBillingentityinternalDescription } from './multilingual-billingentityinternal-description';

/**
 * @type BillingentityinternalResponseCompound
 * A Billingentityinternal Object
 * @export
 */
/** export type BillingentityinternalResponseCompound = BillingentityinternalResponse; */
export interface BillingentityinternalResponseCompound {
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof BillingentityinternalResponseCompound
     */
    pkiBillingentityinternalID:number 
    /**
     * 
     * @type {MultilingualBillingentityinternalDescription}
     * @memberof BillingentityinternalResponseCompound
     */
    objBillingentityinternalDescription:MultilingualBillingentityinternalDescription 
    /**
     * 
     * @type {Array<BillingentityinternalproductResponseCompound>}
     * @memberof BillingentityinternalResponseCompound
     */
    a_objBillingentityinternalproduct:Array<BillingentityinternalproductResponseCompound> 
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
 * A BillingentityinternalResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityinternalResponseCompound
 */
export class DataObjectBillingentityinternalResponseCompound {
    pkiBillingentityinternalID:number = 0
    objBillingentityinternalDescription:MultilingualBillingentityinternalDescription = new DataObjectMultilingualBillingentityinternalDescription()
    a_objBillingentityinternalproduct:Array<BillingentityinternalproductResponseCompound> = []
}

/**
 * @export 
 * A BillingentityinternalResponseCompound Validation Object
 * @class ValidationObjectBillingentityinternalResponseCompound
 */
export class ValidationObjectBillingentityinternalResponseCompound {
   pkiBillingentityinternalID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   objBillingentityinternalDescription = new ValidationObjectMultilingualBillingentityinternalDescription()
   a_objBillingentityinternalproduct = {
      type: 'array',
      required: true
   }
} 


