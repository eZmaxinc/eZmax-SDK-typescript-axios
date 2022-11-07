/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateResponseCompound } from './ezsigntemplate-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagemembershipResponseCompound } from './ezsigntemplatepackagemembership-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagesignermembershipResponseCompound } from './ezsigntemplatepackagesignermembership-response-compound';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatepackagemembershipGetObjectV1ResponseMPayload
 * Payload for GET /1/object/ezsigntemplatepackagemembership/{pkiEzsigntemplatepackagemembershipID}
 * @export
 */
export type EzsigntemplatepackagemembershipGetObjectV1ResponseMPayload = EzsigntemplatepackagemembershipResponseCompound;


/**
 * @export 
 * A EzsigntemplatepackagemembershipGetObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatepackagemembershipGetObjectV1ResponseMPayload
 */
export class DefaultObjectEzsigntemplatepackagemembershipGetObjectV1ResponseMPayload extends DefaultObject {
   pkiEzsigntemplatepackagemembershipID:number = 0
   fkiEzsigntemplatepackageID:number = 0
   fkiEzsigntemplateID:number = 0
   iEzsigntemplatepackagemembershipOrder:number = 0
   objEzsigntemplate:Partial<EzsigntemplateResponseCompound> = {}
   a_objEzsigntemplatepackagesignermembership:Array<EzsigntemplatepackagesignermembershipResponseCompound> = []
}


