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
import { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import { CustomEzsignfoldertransmissionResponse } from './custom-ezsignfoldertransmission-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendtransmissionResponse } from './ezsignbulksendtransmission-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendtransmissionResponseCompoundAllOf } from './ezsignbulksendtransmission-response-compound-all-of';

import { DefaultObject } from '../base'

/**
 * @type EzsignbulksendtransmissionResponseCompound
 * An Ezsignbulksendtransmission Object and children to create a complete structure
 * @export
 */
export type EzsignbulksendtransmissionResponseCompound = EzsignbulksendtransmissionResponse & EzsignbulksendtransmissionResponseCompoundAllOf;


/**
 * @export 
 * A EzsignbulksendtransmissionResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignbulksendtransmissionResponseCompound
 */
export class DefaultObjectEzsignbulksendtransmissionResponseCompound extends DefaultObject {
   pkiEzsignbulksendtransmissionID:number = 0
   fkiEzsignbulksendID:number = 0
   sEzsignbulksendtransmissionDescription:string = ''
   iEzsignbulksendtransmissionErrors:number = 0
   objAudit:Partial<CommonAudit> = {}
   a_objEzsignfoldertransmission:Array<CustomEzsignfoldertransmissionResponse> = []
}


