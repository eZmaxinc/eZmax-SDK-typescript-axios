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
import { DescriptionstaticResponseCompound } from './descriptionstatic-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EmailstaticResponseCompound } from './emailstatic-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { FieldECommunicationrecipientObjecttype } from './field-ecommunicationrecipient-objecttype';
// May contain unused imports in some cases
// @ts-ignore
import { FieldECommunicationrecipientType } from './field-ecommunicationrecipient-type';
// May contain unused imports in some cases
// @ts-ignore
import { PhonestaticResponseCompound } from './phonestatic-response-compound';

/**
 * A Communicationrecipient Object
 * @export
 * @interface CommunicationrecipientResponse
 */
export interface CommunicationrecipientResponse {
    /**
     * The unique ID of the Communicationrecipient.
     * @type {number}
     * @memberof CommunicationrecipientResponse
     */
    'pkiCommunicationrecipientID': number;
    /**
     * 
     * @type {FieldECommunicationrecipientObjecttype}
     * @memberof CommunicationrecipientResponse
     */
    'eCommunicationrecipientObjecttype'?: FieldECommunicationrecipientObjecttype;
    /**
     * The unique ID of the Agent.
     * @type {number}
     * @memberof CommunicationrecipientResponse
     */
    'fkiAgentID'?: number;
    /**
     * The unique ID of the Broker.
     * @type {number}
     * @memberof CommunicationrecipientResponse
     */
    'fkiBrokerID'?: number;
    /**
     * The unique ID of the Contact
     * @type {number}
     * @memberof CommunicationrecipientResponse
     */
    'fkiContactID'?: number;
    /**
     * The unique ID of the Customer.
     * @type {number}
     * @memberof CommunicationrecipientResponse
     */
    'fkiCustomerID'?: number;
    /**
     * The unique ID of the Employee.
     * @type {number}
     * @memberof CommunicationrecipientResponse
     */
    'fkiEmployeeID'?: number;
    /**
     * The unique ID of the Ezsignsigner
     * @type {number}
     * @memberof CommunicationrecipientResponse
     */
    'fkiEzsignsignerID'?: number;
    /**
     * The unique ID of the Franchisereoffice
     * @type {number}
     * @memberof CommunicationrecipientResponse
     */
    'fkiFranchiseofficeID'?: number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof CommunicationrecipientResponse
     */
    'fkiUserID'?: number;
    /**
     * The unique ID of the Agentincorporation.
     * @type {number}
     * @memberof CommunicationrecipientResponse
     */
    'fkiAgentincorporationID'?: number;
    /**
     * The unique ID of the Assistant.
     * @type {number}
     * @memberof CommunicationrecipientResponse
     */
    'fkiAssistantID'?: number;
    /**
     * The unique ID of the Externalbroker.
     * @type {number}
     * @memberof CommunicationrecipientResponse
     */
    'fkiExternalbrokerID'?: number;
    /**
     * The unique ID of the Ezcomagent.
     * @type {number}
     * @memberof CommunicationrecipientResponse
     */
    'fkiEzcomagentID'?: number;
    /**
     * The unique ID of the Notary.
     * @type {number}
     * @memberof CommunicationrecipientResponse
     */
    'fkiNotaryID'?: number;
    /**
     * The unique ID of the Rewardmember.
     * @type {number}
     * @memberof CommunicationrecipientResponse
     */
    'fkiRewardmemberID'?: number;
    /**
     * The unique ID of the Supplier.
     * @type {number}
     * @memberof CommunicationrecipientResponse
     */
    'fkiSupplierID'?: number;
    /**
     * 
     * @type {FieldECommunicationrecipientType}
     * @memberof CommunicationrecipientResponse
     */
    'eCommunicationrecipientType': FieldECommunicationrecipientType;
    /**
     * 
     * @type {DescriptionstaticResponseCompound}
     * @memberof CommunicationrecipientResponse
     */
    'objDescriptionstatic': DescriptionstaticResponseCompound;
    /**
     * 
     * @type {EmailstaticResponseCompound}
     * @memberof CommunicationrecipientResponse
     */
    'objEmailstatic'?: EmailstaticResponseCompound;
    /**
     * 
     * @type {PhonestaticResponseCompound}
     * @memberof CommunicationrecipientResponse
     */
    'objPhonestatic'?: PhonestaticResponseCompound;
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectDescriptionstaticResponseCompound } from './'
// @ts-ignore
import { DataObjectEmailstaticResponseCompound } from './'
// @ts-ignore
import { DataObjectPhonestaticResponseCompound } from './'
// @ts-ignore
import { ValidationObjectDescriptionstaticResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEmailstaticResponseCompound } from './'
// @ts-ignore
import { ValidationObjectPhonestaticResponseCompound } from './'

/**
 * @export 
 * A CommunicationrecipientResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommunicationrecipientResponse
 */
export class DataObjectCommunicationrecipientResponse {
   pkiCommunicationrecipientID:number = 0
   eCommunicationrecipientObjecttype?:FieldECommunicationrecipientObjecttype = undefined
   fkiAgentID?:number = undefined
   fkiBrokerID?:number = undefined
   fkiContactID?:number = undefined
   fkiCustomerID?:number = undefined
   fkiEmployeeID?:number = undefined
   fkiEzsignsignerID?:number = undefined
   fkiFranchiseofficeID?:number = undefined
   fkiUserID?:number = undefined
   fkiAgentincorporationID?:number = undefined
   fkiAssistantID?:number = undefined
   fkiExternalbrokerID?:number = undefined
   fkiEzcomagentID?:number = undefined
   fkiNotaryID?:number = undefined
   fkiRewardmemberID?:number = undefined
   fkiSupplierID?:number = undefined
   eCommunicationrecipientType:FieldECommunicationrecipientType = 'To'
   objDescriptionstatic:DescriptionstaticResponseCompound = new DataObjectDescriptionstaticResponseCompound()
   objEmailstatic?:EmailstaticResponseCompound = undefined
   objPhonestatic?:PhonestaticResponseCompound = undefined
}

/**
 * @export 
 * A CommunicationrecipientResponse Validation Object
 * @class ValidationObjectCommunicationrecipientResponse
 */
export class ValidationObjectCommunicationrecipientResponse {
   pkiCommunicationrecipientID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   eCommunicationrecipientObjecttype = {
      type: 'enum',
      allowableValues: ['Agent','Agentincorporation','Assistant','Broker','Contact','Customer','Employee','Externalbroker','Ezcomagent','Ezcomcompany','Ezsignsigner','Franchiseoffice','Notary','Rewardmember','Supplier','User'],
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
   fkiEzsignsignerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiFranchiseofficeID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiAgentincorporationID = {
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
   fkiEzcomagentID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiNotaryID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiRewardmemberID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiSupplierID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   eCommunicationrecipientType = {
      type: 'enum',
      allowableValues: ['To','Cc','Bcc'],
      required: true
   }
   objDescriptionstatic = new ValidationObjectDescriptionstaticResponseCompound()
   objEmailstatic = new ValidationObjectEmailstaticResponseCompound()
   objPhonestatic = new ValidationObjectPhonestaticResponseCompound()
} 


