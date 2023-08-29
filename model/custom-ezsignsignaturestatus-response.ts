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
 * A Ezsignsignaturestatus Object and children to create a complete structure
 * @export
 * @interface CustomEzsignsignaturestatusResponse
 */
export interface CustomEzsignsignaturestatusResponse {
    /**
     * Type of step
     * @type {string}
     * @memberof CustomEzsignsignaturestatusResponse
     */
    'eEzsignsignaturestatusSteptype': CustomEzsignsignaturestatusResponseEEzsignsignaturestatusSteptypeEnum;
    /**
     * The step at which the Ezsignsigner will be invited to sign or fill the form fields
     * @type {number}
     * @memberof CustomEzsignsignaturestatusResponse
     */
    'iEzsignsignaturestatusStep': number;
    /**
     * The total number of signature or form fields the Ezsignsigner must process at the current step
     * @type {number}
     * @memberof CustomEzsignsignaturestatusResponse
     */
    'iEzsignsignaturestatusTotal': number;
    /**
     * The number of signature or form fields the Ezsignsigner has already processed at the current step
     * @type {number}
     * @memberof CustomEzsignsignaturestatusResponse
     */
    'iEzsignsignaturestatusSigned': number;
}

export const CustomEzsignsignaturestatusResponseEEzsignsignaturestatusSteptypeEnum = {
    Form: 'Form',
    Signature: 'Signature'
} as const;
export type CustomEzsignsignaturestatusResponseEEzsignsignaturestatusSteptypeEnum = typeof CustomEzsignsignaturestatusResponseEEzsignsignaturestatusSteptypeEnum[keyof typeof CustomEzsignsignaturestatusResponseEEzsignsignaturestatusSteptypeEnum];


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzsignsignaturestatusResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzsignsignaturestatusResponse
 */
export class DataObjectCustomEzsignsignaturestatusResponse {
   eEzsignsignaturestatusSteptype:CustomEzsignsignaturestatusResponseEEzsignsignaturestatusSteptypeEnum = 'Form'
   iEzsignsignaturestatusStep:number = 0
   iEzsignsignaturestatusTotal:number = 0
   iEzsignsignaturestatusSigned:number = 0
}

/**
 * @export 
 * A CustomEzsignsignaturestatusResponse Validation Object
 * @class ValidationObjectCustomEzsignsignaturestatusResponse
 */
export class ValidationObjectCustomEzsignsignaturestatusResponse {
   eEzsignsignaturestatusSteptype = {
      type: 'string',
      required: true
   }
   iEzsignsignaturestatusStep = {
      type: 'integer',
      required: true
   }
   iEzsignsignaturestatusTotal = {
      type: 'integer',
      required: true
   }
   iEzsignsignaturestatusSigned = {
      type: 'integer',
      required: true
   }
} 


