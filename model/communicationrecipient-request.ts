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
import { FieldECommunicationrecipientType } from './field-ecommunicationrecipient-type';

/**
 * A Communicationrecipient Object
 * @export
 * @interface CommunicationrecipientRequest
 */
export interface CommunicationrecipientRequest {
    /**
     * The unique ID of the Communicationrecipient.
     * @type {number}
     * @memberof CommunicationrecipientRequest
     */
    'pkiCommunicationrecipientID'?: number;
    /**
     * The unique ID of the Agent.
     * @type {number}
     * @memberof CommunicationrecipientRequest
     */
    'fkiAgentID'?: number;
    /**
     * The unique ID of the Broker.
     * @type {number}
     * @memberof CommunicationrecipientRequest
     */
    'fkiBrokerID'?: number;
    /**
     * The unique ID of the Contact
     * @type {number}
     * @memberof CommunicationrecipientRequest
     */
    'fkiContactID'?: number;
    /**
     * The unique ID of the Customer.
     * @type {number}
     * @memberof CommunicationrecipientRequest
     */
    'fkiCustomerID'?: number;
    /**
     * The unique ID of the Employee.
     * @type {number}
     * @memberof CommunicationrecipientRequest
     */
    'fkiEmployeeID'?: number;
    /**
     * The unique ID of the Assistant.
     * @type {number}
     * @memberof CommunicationrecipientRequest
     */
    'fkiAssistantID'?: number;
    /**
     * The unique ID of the Externalbroker.
     * @type {number}
     * @memberof CommunicationrecipientRequest
     */
    'fkiExternalbrokerID'?: number;
    /**
     * The unique ID of the Ezsignsigner
     * @type {number}
     * @memberof CommunicationrecipientRequest
     */
    'fkiEzsignsignerID'?: number;
    /**
     * The unique ID of the Notary.
     * @type {number}
     * @memberof CommunicationrecipientRequest
     */
    'fkiNotaryID'?: number;
    /**
     * The unique ID of the Supplier.
     * @type {number}
     * @memberof CommunicationrecipientRequest
     */
    'fkiSupplierID'?: number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof CommunicationrecipientRequest
     */
    'fkiUserID'?: number;
    /**
     * The unique ID of the Mailboxshared
     * @type {number}
     * @memberof CommunicationrecipientRequest
     */
    'fkiMailboxsharedID'?: number;
    /**
     * The unique ID of the Phonelineshared
     * @type {number}
     * @memberof CommunicationrecipientRequest
     */
    'fkiPhonelinesharedID'?: number;
    /**
     * 
     * @type {FieldECommunicationrecipientType}
     * @memberof CommunicationrecipientRequest
     */
    'eCommunicationrecipientType'?: FieldECommunicationrecipientType;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CommunicationrecipientRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommunicationrecipientRequest
 */
export class DataObjectCommunicationrecipientRequest {
   pkiCommunicationrecipientID?:number = undefined
   fkiAgentID?:number = undefined
   fkiBrokerID?:number = undefined
   fkiContactID?:number = undefined
   fkiCustomerID?:number = undefined
   fkiEmployeeID?:number = undefined
   fkiAssistantID?:number = undefined
   fkiExternalbrokerID?:number = undefined
   fkiEzsignsignerID?:number = undefined
   fkiNotaryID?:number = undefined
   fkiSupplierID?:number = undefined
   fkiUserID?:number = undefined
   fkiMailboxsharedID?:number = undefined
   fkiPhonelinesharedID?:number = undefined
   eCommunicationrecipientType?:FieldECommunicationrecipientType = undefined
}

/**
 * @export 
 * A CommunicationrecipientRequest Validation Object
 * @class ValidationObjectCommunicationrecipientRequest
 */
export class ValidationObjectCommunicationrecipientRequest {
   pkiCommunicationrecipientID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
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
   fkiContactID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiCustomerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEmployeeID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiAssistantID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiExternalbrokerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignsignerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiNotaryID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiSupplierID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiUserID = {
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
   fkiPhonelinesharedID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   eCommunicationrecipientType = {
      type: 'enum',
      allowableValues: ['To','Cc','Bcc'],
      required: false
   }
} 


