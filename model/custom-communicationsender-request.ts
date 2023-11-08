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



/**
 * A Communicationsender Object
 * @export
 * @interface CustomCommunicationsenderRequest
 */
export interface CustomCommunicationsenderRequest {
    /**
     * The unique ID of the Agent.
     * @type {number}
     * @memberof CustomCommunicationsenderRequest
     */
    'fkiAgentID'?: number;
    /**
     * The unique ID of the Broker.
     * @type {number}
     * @memberof CustomCommunicationsenderRequest
     */
    'fkiBrokerID'?: number;
    /**
     * The unique ID of the Mailboxshared
     * @type {number}
     * @memberof CustomCommunicationsenderRequest
     */
    'fkiMailboxsharedID'?: number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof CustomCommunicationsenderRequest
     */
    'fkiUserID'?: number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomCommunicationsenderRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomCommunicationsenderRequest
 */
export class DataObjectCustomCommunicationsenderRequest {
   fkiAgentID?:number = undefined
   fkiBrokerID?:number = undefined
   fkiMailboxsharedID?:number = undefined
   fkiUserID?:number = undefined
}

/**
 * @export 
 * A CustomCommunicationsenderRequest Validation Object
 * @class ValidationObjectCustomCommunicationsenderRequest
 */
export class ValidationObjectCustomCommunicationsenderRequest {
   fkiAgentID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiBrokerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiMailboxsharedID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
} 


