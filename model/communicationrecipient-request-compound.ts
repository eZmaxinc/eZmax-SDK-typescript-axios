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
import { CommunicationrecipientRequest } from './communicationrecipient-request';
// May contain unused imports in some cases
// @ts-ignore
import { FieldECommunicationrecipientType } from './field-ecommunicationrecipient-type';

/**
 * @type CommunicationrecipientRequestCompound
 * A Communicationrecipient Object and children
 * @export
 */
/** export type CommunicationrecipientRequestCompound = CommunicationrecipientRequest; */
export interface CommunicationrecipientRequestCompound {
    /**
     * The unique ID of the Communicationrecipient.
     * @type {number}
     * @memberof CommunicationrecipientRequestCompound
     */
    pkiCommunicationrecipientID?:number 
    /**
     * The unique ID of the Agent.
     * @type {number}
     * @memberof CommunicationrecipientRequestCompound
     */
    fkiAgentID?:number 
    /**
     * The unique ID of the Agentincorporation.
     * @type {number}
     * @memberof CommunicationrecipientRequestCompound
     */
    fkiAgentincorporationID?:number 
    /**
     * The unique ID of the Broker.
     * @type {number}
     * @memberof CommunicationrecipientRequestCompound
     */
    fkiBrokerID?:number 
    /**
     * The unique ID of the Customer.
     * @type {number}
     * @memberof CommunicationrecipientRequestCompound
     */
    fkiCustomerID?:number 
    /**
     * The unique ID of the Employee.
     * @type {number}
     * @memberof CommunicationrecipientRequestCompound
     */
    fkiEmployeeID?:number 
    /**
     * The unique ID of the Assistant.
     * @type {number}
     * @memberof CommunicationrecipientRequestCompound
     */
    fkiAssistantID?:number 
    /**
     * The unique ID of the Externalbroker.
     * @type {number}
     * @memberof CommunicationrecipientRequestCompound
     */
    fkiExternalbrokerID?:number 
    /**
     * The unique ID of the Ezsignsigner
     * @type {number}
     * @memberof CommunicationrecipientRequestCompound
     */
    fkiEzsignsignerID?:number 
    /**
     * The unique ID of the Notary.
     * @type {number}
     * @memberof CommunicationrecipientRequestCompound
     */
    fkiNotaryID?:number 
    /**
     * The unique ID of the Supplier.
     * @type {number}
     * @memberof CommunicationrecipientRequestCompound
     */
    fkiSupplierID?:number 
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof CommunicationrecipientRequestCompound
     */
    fkiUserID?:number 
    /**
     * 
     * @type {FieldECommunicationrecipientType}
     * @memberof CommunicationrecipientRequestCompound
     */
    eCommunicationrecipientType?:FieldECommunicationrecipientType 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CommunicationrecipientRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommunicationrecipientRequestCompound
 */
export class DataObjectCommunicationrecipientRequestCompound {
    pkiCommunicationrecipientID?:number = undefined
    fkiAgentID?:number = undefined
    fkiAgentincorporationID?:number = undefined
    fkiBrokerID?:number = undefined
    fkiCustomerID?:number = undefined
    fkiEmployeeID?:number = undefined
    fkiAssistantID?:number = undefined
    fkiExternalbrokerID?:number = undefined
    fkiEzsignsignerID?:number = undefined
    fkiNotaryID?:number = undefined
    fkiSupplierID?:number = undefined
    fkiUserID?:number = undefined
    eCommunicationrecipientType?:FieldECommunicationrecipientType = undefined
}

/**
 * @export 
 * A CommunicationrecipientRequestCompound Validation Object
 * @class ValidationObjectCommunicationrecipientRequestCompound
 */
export class ValidationObjectCommunicationrecipientRequestCompound {
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
   fkiAgentincorporationID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiBrokerID = {
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
   eCommunicationrecipientType = {
      type: 'enum',
      allowableValues: ['To','Cc','Bcc'],
      required: false
   }
} 


