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
import { CustomCommunicationsenderRequest } from './custom-communicationsender-request';
// May contain unused imports in some cases
// @ts-ignore
import { FieldECommunicationImportance } from './field-ecommunication-importance';
// May contain unused imports in some cases
// @ts-ignore
import { FieldECommunicationType } from './field-ecommunication-type';

/**
 * Request for POST /1/object/communication
 * @export
 * @interface CommunicationRequest
 */
export interface CommunicationRequest {
    /**
     * The unique ID of the Communication.
     * @type {number}
     * @memberof CommunicationRequest
     */
    'pkiCommunicationID'?: number;
    /**
     * 
     * @type {FieldECommunicationImportance}
     * @memberof CommunicationRequest
     */
    'eCommunicationImportance'?: FieldECommunicationImportance;
    /**
     * 
     * @type {FieldECommunicationType}
     * @memberof CommunicationRequest
     */
    'eCommunicationType': FieldECommunicationType;
    /**
     * 
     * @type {CustomCommunicationsenderRequest}
     * @memberof CommunicationRequest
     */
    'objCommunicationsender'?: CustomCommunicationsenderRequest;
    /**
     * The subject of the Communication
     * @type {string}
     * @memberof CommunicationRequest
     */
    'sCommunicationSubject'?: string;
    /**
     * The Body of the Communication
     * @type {string}
     * @memberof CommunicationRequest
     */
    'tCommunicationBody': string;
    /**
     * Whether the Communication is private or not
     * @type {boolean}
     * @memberof CommunicationRequest
     */
    'bCommunicationPrivate': boolean;
    /**
     * How the attachment should be included in the email.   Only used if eCommunicationType is **Email**
     * @type {string}
     * @memberof CommunicationRequest
     */
    'eCommunicationAttachmenttype'?: CommunicationRequestECommunicationAttachmenttypeEnum;
    /**
     * The number of days before the attachment link expired.   Only used if eCommunicationType is **Email** and eCommunicationattachmentType is **Link**
     * @type {number}
     * @memberof CommunicationRequest
     */
    'iCommunicationAttachmentlinkexpiration'?: number;
    /**
     * Whether we ask for a read receipt or not.
     * @type {boolean}
     * @memberof CommunicationRequest
     */
    'bCommunicationReadreceipt'?: boolean;
}

export const CommunicationRequestECommunicationAttachmenttypeEnum = {
    Attachment: 'Attachment',
    Url: 'Url'
} as const;
export type CommunicationRequestECommunicationAttachmenttypeEnum = typeof CommunicationRequestECommunicationAttachmenttypeEnum[keyof typeof CommunicationRequestECommunicationAttachmenttypeEnum];


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCustomCommunicationsenderRequest } from './'
// @ts-ignore
import { ValidationObjectCustomCommunicationsenderRequest } from './'

/**
 * @export 
 * A CommunicationRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommunicationRequest
 */
export class DataObjectCommunicationRequest {
   pkiCommunicationID?:number = undefined
   eCommunicationImportance?:FieldECommunicationImportance = undefined
   eCommunicationType:FieldECommunicationType = 'Email'
   objCommunicationsender?:CustomCommunicationsenderRequest = undefined
   sCommunicationSubject?:string = undefined
   tCommunicationBody:string = ''
   bCommunicationPrivate:boolean = false
   eCommunicationAttachmenttype?:CommunicationRequestECommunicationAttachmenttypeEnum = undefined
   iCommunicationAttachmentlinkexpiration?:number = undefined
   bCommunicationReadreceipt?:boolean = undefined
}

/**
 * @export 
 * A CommunicationRequest Validation Object
 * @class ValidationObjectCommunicationRequest
 */
export class ValidationObjectCommunicationRequest {
   pkiCommunicationID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   eCommunicationImportance = {
      type: 'enum',
      allowableValues: ['High','Normal','Low'],
      required: false
   }
   eCommunicationType = {
      type: 'enum',
      allowableValues: ['Email','Fax','Sms'],
      required: true
   }
   objCommunicationsender = new ValidationObjectCustomCommunicationsenderRequest()
   sCommunicationSubject = {
      type: 'string',
      pattern: '/^.{0,150}$/',
      required: false
   }
   tCommunicationBody = {
      type: 'string',
      required: true
   }
   bCommunicationPrivate = {
      type: 'boolean',
      required: true
   }
   eCommunicationAttachmenttype = {
      type: 'string',
      required: false
   }
   iCommunicationAttachmentlinkexpiration = {
      type: 'integer',
      minimum: 1,
      maximum: 30,
      required: false
   }
   bCommunicationReadreceipt = {
      type: 'boolean',
      required: false
   }
} 

