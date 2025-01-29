/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Request for POST /1/object/billingentityexternal/{pkiBillingentityexternalID}/generateFederationToken
 * @export
 * @interface BillingentityexternalGenerateFederationTokenV1Request
 */
export interface BillingentityexternalGenerateFederationTokenV1Request {
    /**
     * The Ezmaxcustomer code
     * @type {string}
     * @memberof BillingentityexternalGenerateFederationTokenV1Request
     */
    /*'fksEzmaxcustomerCode': string;*/
    'fksEzmaxcustomerCode': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A BillingentityexternalGenerateFederationTokenV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBillingentityexternalGenerateFederationTokenV1Request
 */
export class DataObjectBillingentityexternalGenerateFederationTokenV1Request {
   fksEzmaxcustomerCode:string = ''
}

/**
 * @export 
 * A BillingentityexternalGenerateFederationTokenV1Request Validation Object
 * @class ValidationObjectBillingentityexternalGenerateFederationTokenV1Request
 */
export class ValidationObjectBillingentityexternalGenerateFederationTokenV1Request {
   fksEzmaxcustomerCode = {
      type: 'string',
      pattern: /^[a-z\d]{2,6}$/,
      minLength: 2,
      maxLength: 6,
      required: true
   }
} 


