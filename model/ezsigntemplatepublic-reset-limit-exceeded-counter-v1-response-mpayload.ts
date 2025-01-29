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
 * Payload for POST /1/object/ezsigntemplatepublic/{pkiEzsigntemplatepublicID}/resetLimitExceededCounter
 * @export
 * @interface EzsigntemplatepublicResetLimitExceededCounterV1ResponseMPayload
 */
export interface EzsigntemplatepublicResetLimitExceededCounterV1ResponseMPayload {
    /**
     * The limitexceededsince of the Ezsigntemplatepublic
     * @type {string}
     * @memberof EzsigntemplatepublicResetLimitExceededCounterV1ResponseMPayload
     */
    /*'dtEzsigntemplatepublicLimitexceededsince': string;*/
    'dtEzsigntemplatepublicLimitexceededsince': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepublicResetLimitExceededCounterV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepublicResetLimitExceededCounterV1ResponseMPayload
 */
export class DataObjectEzsigntemplatepublicResetLimitExceededCounterV1ResponseMPayload {
   dtEzsigntemplatepublicLimitexceededsince:string = ''
}

/**
 * @export 
 * A EzsigntemplatepublicResetLimitExceededCounterV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatepublicResetLimitExceededCounterV1ResponseMPayload
 */
export class ValidationObjectEzsigntemplatepublicResetLimitExceededCounterV1ResponseMPayload {
   dtEzsigntemplatepublicLimitexceededsince = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/,
      required: true
   }
} 


