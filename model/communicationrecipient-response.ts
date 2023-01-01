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
import { FieldECommunicationrecipientType } from './field-ecommunicationrecipient-type';
// May contain unused imports in some cases
// @ts-ignore
import { PhoneResponseCompound } from './phone-response-compound';

import { DefaultObject } from '../base'

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
     * The email address.
     * @type {string}
     * @memberof CommunicationrecipientResponse
     */
    'sEmailAddress'?: string;
    /**
     * 
     * @type {FieldECommunicationrecipientType}
     * @memberof CommunicationrecipientResponse
     */
    'eCommunicationrecipientType'?: FieldECommunicationrecipientType;
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
     * @type {PhoneResponseCompound}
     * @memberof CommunicationrecipientResponse
     */
    'objPhoneSms'?: PhoneResponseCompound;
}
/**
 * A CommunicationrecipientResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCommunicationrecipientResponse
 */
export class DefaultObjectCommunicationrecipientResponse extends DefaultObject {
   pkiCommunicationrecipientID:number = 0
   fkiAgentID?:number = undefined
   fkiBrokerID?:number = undefined
   fkiContactID?:number = undefined
   fkiCustomerID?:number = undefined
   fkiEmployeeID?:number = undefined
   fkiEzsignsignerID?:number = undefined
   fkiFranchiseofficeID?:number = undefined
   fkiUserID?:number = undefined
   sEmailAddress?:string = undefined
   eCommunicationrecipientType?:FieldECommunicationrecipientType = undefined
   fkiAgentincorporationID?:number = undefined
   fkiAssistantID?:number = undefined
   fkiExternalbrokerID?:number = undefined
   fkiEzcomagentID?:number = undefined
   fkiNotaryID?:number = undefined
   fkiRewardmemberID?:number = undefined
   fkiSupplierID?:number = undefined
   objPhoneSms?:Partial<PhoneResponseCompound> = undefined
}


