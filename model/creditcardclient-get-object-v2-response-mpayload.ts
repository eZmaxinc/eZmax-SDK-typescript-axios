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
import { CreditcardclientResponseCompound } from './creditcardclient-response-compound';

/**
 * Payload for GET /2/object/creditcardclient/{pkiCreditcardclientID}
 * @export
 * @interface CreditcardclientGetObjectV2ResponseMPayload
 */
export interface CreditcardclientGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {CreditcardclientResponseCompound}
     * @memberof CreditcardclientGetObjectV2ResponseMPayload
     */
    /*'objCreditcardclient': CreditcardclientResponseCompound;*/
    'objCreditcardclient': CreditcardclientResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCreditcardclientResponseCompound } from './'
// @ts-ignore
import { ValidationObjectCreditcardclientResponseCompound } from './'

/**
 * @export 
 * A CreditcardclientGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCreditcardclientGetObjectV2ResponseMPayload
 */
export class DataObjectCreditcardclientGetObjectV2ResponseMPayload {
   objCreditcardclient:CreditcardclientResponseCompound = new DataObjectCreditcardclientResponseCompound()
}

/**
 * @export 
 * A CreditcardclientGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectCreditcardclientGetObjectV2ResponseMPayload
 */
export class ValidationObjectCreditcardclientGetObjectV2ResponseMPayload {
   objCreditcardclient = new ValidationObjectCreditcardclientResponseCompound()
} 

