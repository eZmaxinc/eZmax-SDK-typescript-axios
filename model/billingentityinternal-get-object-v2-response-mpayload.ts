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
import { BillingentityinternalResponseCompound } from './billingentityinternal-response-compound';

/**
 * Payload for GET /2/object/billingentityinternal/{pkiBillingentityinternalID}
 * @export
 * @interface BillingentityinternalGetObjectV2ResponseMPayload
 */
export interface BillingentityinternalGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {BillingentityinternalResponseCompound}
     * @memberof BillingentityinternalGetObjectV2ResponseMPayload
     */
    'objBillingentityinternal': BillingentityinternalResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectBillingentityinternalResponseCompound } from './'
// @ts-ignore
import { ValidationObjectBillingentityinternalResponseCompound } from './'

/**
 * @export 
 * A BillingentityinternalGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityinternalGetObjectV2ResponseMPayload
 */
export class DataObjectBillingentityinternalGetObjectV2ResponseMPayload {
   objBillingentityinternal:BillingentityinternalResponseCompound = new DataObjectBillingentityinternalResponseCompound()
}

/**
 * @export 
 * A BillingentityinternalGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectBillingentityinternalGetObjectV2ResponseMPayload
 */
export class ValidationObjectBillingentityinternalGetObjectV2ResponseMPayload {
   objBillingentityinternal = new ValidationObjectBillingentityinternalResponseCompound()
} 


