/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
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
import { CustomEzsignfoldersignerassociationstatusResponse } from './custom-ezsignfoldersignerassociationstatus-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentResponse } from './ezsigndocument-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentResponseCompoundAllOf } from './ezsigndocument-response-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigndocumentStep } from './field-eezsigndocument-step';

import { DefaultObject } from '../base'

/**
 * @type EzsigndocumentResponseCompound
 * An Ezsigndocument Object and children to create a complete structure
 * @export
 */
export type EzsigndocumentResponseCompound = EzsigndocumentResponse & EzsigndocumentResponseCompoundAllOf;


/**
 * @export 
 * A EzsigndocumentResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigndocumentResponseCompound
 */
export class DefaultObjectEzsigndocumentResponseCompound extends DefaultObject {
   fkiEzsignfolderID:number = 0
   dtEzsigndocumentDuedate:string = ''
   dtEzsignformCompleted?:string = undefined
   fkiLanguageID:number = 0
   sEzsigndocumentName:string = ''
   pkiEzsigndocumentID:number = 0
   eEzsigndocumentStep:FieldEEzsigndocumentStep = 'Unsent'
   dtEzsigndocumentFirstsend?:string = undefined
   dtEzsigndocumentLastsend?:string = undefined
   iEzsigndocumentOrder:number = 0
   iEzsigndocumentPagetotal:number = 0
   iEzsigndocumentSignaturesigned:number = 0
   iEzsigndocumentSignaturetotal:number = 0
   sEzsigndocumentMD5initial:string = ''
   sEzsigndocumentMD5signed:string = ''
   bEzsigndocumentEzsignform:boolean = false
   objAudit:Partial<CommonAudit> = {}
   iEzsigndocumentStepformtotal:number = 0
   iEzsigndocumentStepformcurrent:number = 0
   iEzsigndocumentStepsignaturetotal:number = 0
   iEzsigndocumentStepsignatureCurrent:number = 0
   a_objEzsignfoldersignerassociationstatus:Array<CustomEzsignfoldersignerassociationstatusResponse> = []
}


