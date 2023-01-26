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
import { CommunicationrecipientResponse } from './communicationrecipient-response';
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

import { DefaultObject } from '../base'

/**
 * @type CommunicationrecipientResponseCompound
 * A Communicationreciient Object
 * @export
 */
export type CommunicationrecipientResponseCompound = CommunicationrecipientResponse;


/**
 * @export 
 * A CommunicationrecipientResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectCommunicationrecipientResponseCompound
 */
export class DefaultObjectCommunicationrecipientResponseCompound extends DefaultObject {
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
   objDescriptionstatic:Partial<DescriptionstaticResponseCompound> = {}
   objEmailstatic?:Partial<EmailstaticResponseCompound> = undefined
   objPhonestatic?:Partial<PhonestaticResponseCompound> = undefined
}


