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
import { CommunicationexternalimageResponse } from './communicationexternalimage-response';

import { DefaultObject } from '../base'

/**
 * @type CommunicationexternalimageResponseCompound
 * A Communicationexternalimage Object
 * @export
 */
export type CommunicationexternalimageResponseCompound = CommunicationexternalimageResponse;


/**
 * @export 
 * A CommunicationexternalimageResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectCommunicationexternalimageResponseCompound
 */
export class DefaultObjectCommunicationexternalimageResponseCompound extends DefaultObject {
   pkiCommunicationexternalimageID:number = 0
   sCommunicationexternalimageMD5:string = ''
}


